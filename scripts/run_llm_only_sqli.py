"""
Claude API(Sonnet 5) 단독 방식으로 --category가 가리키는 CWE 취약점 여부를 판단하는 스크립트.
(과거에는 SQLi 전용이었으나 --category로 일반화함. 파일명은 하위 호환을 위해 유지)

정적분석 결과는 절대 프롬프트에 포함하지 않는다 — Semgrep 단독/LLM 단독/하이브리드
3방식을 공정하게 비교하는 Ablation Study를 위해, 각 단독 방식은 서로의 결과를
참조하지 않고 독립적으로 판단해야 함.

- sources/ 안의 .java 파일을 순회하며 소스 코드만 프롬프트에 넣음
- 응답은 구조화된 JSON({vulnerable, confidence, reasoning})으로 강제
- reasoning은 나중에 설명가능성(explainability) 검증에 쓸 것이므로 구체적 근거를 남기게 함
- 레이트리밋/일시적 오류에 대해 지수 백오프 재시도
- 20건마다 중간 저장 (중단되어도 이어서 확인 가능)
- --mock: 실제 API를 호출하지 않고 소스 코드 해시 기반으로 결정론적인 가짜 응답을
  생성 — API 키 없이도 파이프라인(스크립트 → JSON → 평가)이 끝까지 도는지 검증 가능

사용 예:
    python scripts/run_llm_only_sqli.py --category sqli --mock   # API 키 없이 파이프라인 검증
    python scripts/run_llm_only_sqli.py --category xss           # 실제 Claude API 호출 (ANTHROPIC_API_KEY 필요)
    python scripts/run_llm_only_sqli.py --category cmdi --limit 5  # 소규모 테스트
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import zlib
from pathlib import Path
from random import Random

import anthropic
from pydantic import BaseModel, field_validator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_semgrep import CATEGORY_TO_CWE  # noqa: E402  (카테고리->CWE 매핑을 한 곳에서만 관리)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

MODEL = "claude-sonnet-5"
MAX_RETRIES_PER_CALL = 5
BASE_DELAY_SEC = 2.0
MAX_DELAY_SEC = 60.0

# CATEGORY_TO_CWE의 각 카테고리에 대응하는 사람이 읽는 취약점 이름
CATEGORY_TO_NAME = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting(XSS)",
    "cmdi": "OS Command Injection",
    "pathtraver": "Path Traversal",
    "crypto": "Weak/Insecure Cryptography",
    "hash": "Insecure Hash",
    "weakrand": "Insecure Randomness",
    "trustbound": "Trust Boundary Violation",
    "securecookie": "Insecure Cookie",
    "ldapi": "LDAP Injection",
    "xpathi": "XPath Injection",
    "xxe": "XML External Entities(XXE)",
}


class VulnJudgment(BaseModel):
    vulnerable: bool
    confidence: float
    reasoning: str

    @field_validator("confidence")
    @classmethod
    def _normalize_confidence(cls, v: float) -> float:
        """confidence를 0~1로 정규화한다.

        실측에서 모델이 확률(0.92) 대신 백분율(92.0)로 답하는 경우가 1,478건 중
        22건(1.5%) 발생했다. 스키마가 그냥 float이라 그대로 통과했고, 캐스케이드의
        `confidence >= reject_threshold` 비교에서 백분율 값은 사실상 항상 참이 되어
        threshold 튜닝을 왜곡한다. 1을 넘으면 백분율로 보고 100으로 나눈다.
        """
        if v > 1.0:
            v = v / 100.0
        return min(max(v, 0.0), 1.0)


def build_system_prompt(category: str) -> str:
    cwe = CATEGORY_TO_CWE[category]
    name = CATEGORY_TO_NAME[category]
    return (
        "당신은 보안 취약점 분석 전문가입니다. 주어진 Java 소스 코드 파일 하나를 검토하여 "
        f"{name}(CWE-{cwe}) 취약점이 존재하는지 판단하세요.\n"
        "정적분석 도구의 결과는 제공되지 않습니다 — 오직 소스 코드만 보고 스스로 판단해야 합니다.\n"
        "reasoning 필드에는 구체적인 근거를 남기세요: 어떤 변수가 어디서 사용자 입력을 받는지, "
        "그 값이 어떤 경로(데이터 흐름)로 취약한 싱크(예: 쿼리 실행, 명령 실행, 파일 경로 접근 등 "
        f"{name}에 해당하는 지점)에 도달하는지, 안전하게 처리(검증/이스케이프/파라미터화 등)되는지 여부."
    )


def build_user_prompt(source_code: str, category: str) -> str:
    cwe = CATEGORY_TO_CWE[category]
    name = CATEGORY_TO_NAME[category]
    return (
        f"다음 Java 소스 코드에 {name}(CWE-{cwe}) 취약점이 있는지 판단하세요.\n\n"
        "```java\n"
        f"{source_code}\n"
        "```"
    )


def classify_file_mock(source_code: str) -> VulnJudgment:
    """실제 API를 호출하지 않고, 소스 코드 내용으로 시드를 고정한 가짜 판단을 생성.

    같은 소스 코드는 항상 같은 결과를 내므로(결정론적), 평가 스크립트까지 포함한
    전체 파이프라인이 에러 없이 끝까지 도는지 반복 검증하기 좋음. (카테고리에 무관 —
    가짜 응답이라 어떤 취약점을 판단하는 척하는지는 중요하지 않음)
    """
    seed = zlib.crc32(source_code.encode("utf-8"))
    rng = Random(seed)
    vulnerable = rng.random() < 0.5
    confidence = round(rng.uniform(0.55, 0.99), 2)
    reasoning = (
        "[MOCK] 실제 Claude API를 호출하지 않고 생성된 가짜 응답입니다. "
        f"소스 코드 해시(crc32={seed})를 시드로 사용해 결정론적으로 생성했으며, "
        "실제 취약점 판단 근거가 아니라 파이프라인 검증용 placeholder입니다."
    )
    return VulnJudgment(vulnerable=vulnerable, confidence=confidence, reasoning=reasoning)


def classify_file_via_api(
    client: anthropic.Anthropic, source_code: str, category: str
) -> VulnJudgment:
    """Claude API(Sonnet 5)를 실제로 호출해 category 취약점 여부를 판단. 레이트리밋/일시 오류는 재시도."""
    system_prompt = build_system_prompt(category)
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES_PER_CALL):
        try:
            response = client.messages.parse(
                model=MODEL,
                max_tokens=1024,
                thinking={"type": "disabled"},
                system=system_prompt,
                messages=[{"role": "user", "content": build_user_prompt(source_code, category)}],
                output_format=VulnJudgment,
            )
            if response.parsed_output is None:
                raise ValueError("구조화된 출력 파싱 실패 (parsed_output=None)")
            return response.parsed_output

        except anthropic.RateLimitError as e:
            last_exc = e
            retry_after = 0
            if e.response is not None:
                retry_after = int(e.response.headers.get("retry-after", "0") or 0)
            delay = max(retry_after, min(BASE_DELAY_SEC * (2**attempt), MAX_DELAY_SEC))
            print(f"    [rate-limit] {delay:.0f}초 대기 후 재시도 ({attempt + 1}/{MAX_RETRIES_PER_CALL})")
            time.sleep(delay)

        except anthropic.APIConnectionError as e:
            last_exc = e
            delay = min(BASE_DELAY_SEC * (2**attempt), MAX_DELAY_SEC)
            print(f"    [connection-error] {delay:.0f}초 대기 후 재시도 ({attempt + 1}/{MAX_RETRIES_PER_CALL})")
            time.sleep(delay)

        except anthropic.APIStatusError as e:
            last_exc = e
            if e.status_code >= 500:
                delay = min(BASE_DELAY_SEC * (2**attempt), MAX_DELAY_SEC)
                print(
                    f"    [server-error {e.status_code}] {delay:.0f}초 대기 후 재시도 "
                    f"({attempt + 1}/{MAX_RETRIES_PER_CALL})"
                )
                time.sleep(delay)
            else:
                raise  # 4xx(429 제외)는 재시도해도 소용없음 — 즉시 실패 처리

    raise RuntimeError(f"최대 재시도 횟수({MAX_RETRIES_PER_CALL}) 초과: {last_exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument(
        "--category",
        default="sqli",
        choices=sorted(CATEGORY_TO_CWE),
        help="평가할 카테고리 (기본: sqli)",
    )
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=None,
        help="분석할 .java 소스 디렉토리 (기본: data/processed/<category>/sources)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="결과 JSON 저장 경로 (기본: data/results/<category>/llm/llm_predictions.json)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="처음 N개 파일만 처리 (테스트/스모크 실행용)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="실제 Claude API를 호출하지 않고 결정론적 가짜 응답으로 파이프라인만 검증",
    )
    args = parser.parse_args()

    sources_dir = args.sources_dir or (args.project_root / "data" / "processed" / args.category / "sources")
    output_path = args.output or (
        args.project_root / "data" / "results" / args.category / "llm" / "llm_predictions.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not sources_dir.exists():
        raise FileNotFoundError(f"소스 디렉토리를 찾을 수 없음: {sources_dir}")

    java_files = sorted(sources_dir.glob("*.java"))
    if args.limit:
        java_files = java_files[: args.limit]
    total = len(java_files)
    if total == 0:
        raise FileNotFoundError(f"'{sources_dir}'에 .java 파일이 없음")

    if args.mock:
        print("[MOCK MODE] 실제 Claude API를 호출하지 않습니다 — 가짜 응답으로 파이프라인만 검증합니다.\n")
        client = None
    else:
        client = anthropic.Anthropic()  # ANTHROPIC_API_KEY 환경변수 자동 사용

    results: dict[str, dict] = {}
    start = time.time()

    for i, path in enumerate(java_files, 1):
        test_name = path.stem
        source_code = path.read_text(encoding="utf-8")

        try:
            if args.mock:
                judgment = classify_file_mock(source_code)
            else:
                judgment = classify_file_via_api(client, source_code, args.category)
            results[test_name] = judgment.model_dump()
            results[test_name]["mock"] = args.mock
            status = "VULNERABLE" if judgment.vulnerable else "safe"
        except Exception as e:  # noqa: BLE001 - 개별 실패는 기록하고 배치는 계속 진행
            print(f"    [error] {test_name}: {e}", file=sys.stderr)
            results[test_name] = {
                "vulnerable": None,
                "confidence": None,
                "reasoning": f"API 호출 실패: {e}",
                "error": True,
            }
            status = "ERROR"

        elapsed = time.time() - start
        avg = elapsed / i
        remaining = avg * (total - i)
        print(f"[{i}/{total}] {test_name}: {status}  (경과 {elapsed:.0f}s, 예상 잔여 {remaining:.0f}s)")

        if i % 20 == 0 or i == total:
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    n_errors = sum(1 for r in results.values() if r.get("error"))
    print(f"\n[write] {output_path} ({len(results)}건, 실패 {n_errors}건)")


if __name__ == "__main__":
    main()
