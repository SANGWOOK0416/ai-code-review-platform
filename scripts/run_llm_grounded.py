"""
Claude API(Sonnet 5)로 --category 취약점 여부를 판단하되, Semgrep 탐지 결과를
프롬프트 컨텍스트로 포함하는 "grounded" 경로.

run_llm_only_sqli.py(단독 방식)는 절대 건드리지 않는다 — 두 스크립트를 나란히
둬야 grounded vs ungrounded 비교(measure_grounding.py --compare-json)가 성립한다.
정적분석 결과를 프롬프트에 넣는 게 바로 이 스크립트가 존재하는 이유이므로,
run_llm_only_sqli.py의 "절대 포함하지 않는다"는 설계를 위반하지 않고 별도
경로로 분리했다.

grounding 컨텍스트 설계:
  - 해당 카테고리(CWE)에 해당하는 Semgrep finding만 프롬프트에 넣는다
    (evaluate_semgrep.is_category_finding과 동일한 필터 — merge_hybrid의
    semgrep_detected와 같은 기준이어야 "Semgrep 신호를 grounding으로 줬다"는
    말이 성립함)
  - Semgrep이 아무것도 탐지하지 않았어도 "탐지 없음"을 명시적으로 알려준다.
    지난 세션 우도비 분석(LR- 0.36~0.48)에 따르면 Semgrep의 침묵이 탐지보다
    강한 증거이므로, 이 신호도 판단에 참고하게 하는 것이 grounding의 취지에 맞음
  - Semgrep 결과가 최종 판단이 아니라 "참고 증거"임을 프롬프트에 명시 —
    LLM이 Semgrep을 맹신하면 grounding이 아니라 단순 위임이 되어버림

예산 관리:
  --limit은 "이번 실행에서 새로 호출할 최대 건수"를 의미하며, 이미 결과가 있는
  test_name은 건너뛴다(재실행/이어하기 시 중복 과금 방지). 각 응답의
  usage(input/output 토큰)를 결과에 함께 기록해 실측 비용 계산에 쓸 수 있게 한다.

사용 예:
    # 1) 파일럿 30건으로 실측 단가 확인
    python scripts/run_llm_grounded.py --category sqli --limit 30

    # 2) 이어서 나머지 실행 (이미 된 30건은 건너뜀)
    python scripts/run_llm_grounded.py --category sqli

    # 3) --mock 으로 API 없이 파이프라인만 검증
    python scripts/run_llm_grounded.py --category sqli --mock --limit 5
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import anthropic

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_semgrep import (  # noqa: E402  (필터 기준을 evaluate_semgrep과 통일)
    CATEGORY_TO_CWE,
    CATEGORY_TO_VULN_KEYWORDS,
    is_category_finding,
)
from run_llm_only_sqli import (  # noqa: E402  (스키마/상수 재사용 — 절대 수정하지 않음)
    CATEGORY_TO_NAME,
    MODEL,
    BASE_DELAY_SEC,
    MAX_DELAY_SEC,
    MAX_RETRIES_PER_CALL,
    VulnJudgment,
    classify_file_mock,
)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


def build_system_prompt_grounded(category: str) -> str:
    cwe = CATEGORY_TO_CWE[category]
    name = CATEGORY_TO_NAME[category]
    return (
        "당신은 보안 취약점 분석 전문가입니다. 주어진 Java 소스 코드 파일 하나를 검토하여 "
        f"{name}(CWE-{cwe}) 취약점이 존재하는지 판단하세요.\n"
        "이번에는 정적분석 도구(Semgrep)의 탐지 결과가 참고 컨텍스트로 함께 제공됩니다. "
        "Semgrep은 오탐(안전한데 탐지)과 미탐(놓침)이 모두 발생할 수 있는 도구입니다 — "
        "그 결과를 그대로 따르지 말고, 스스로 코드의 데이터 흐름을 추적해 최종 판단을 내리세요.\n"
        "reasoning 필드에는 구체적인 근거를 남기세요: 어떤 변수가 어디서 사용자 입력을 받는지, "
        "그 값이 어떤 경로(데이터 흐름)로 취약한 싱크에 도달하는지, 안전하게 처리되는지 여부, "
        "그리고 Semgrep 결과에 동의하는지/반박하는지와 그 이유."
    )


def build_findings_context(findings: list[dict], category: str) -> str:
    name = CATEGORY_TO_NAME[category]
    if not findings:
        return (
            f"[Semgrep 정적분석 결과]\nSemgrep은 이 파일에서 {name} 관련 finding을 탐지하지 "
            "않았습니다. (참고용 — Semgrep이 놓쳤을 가능성도 있으니 이 신호만으로 안전하다고 "
            "단정하지 말고 코드를 직접 판단하세요.)"
        )
    lines = [
        f"- [{f['check_id']}] {f['line']}번째 줄 부근: {f['message']}" for f in findings
    ]
    return (
        f"[Semgrep 정적분석 결과]\nSemgrep이 이 파일에서 {name} 관련 finding을 "
        f"{len(findings)}건 탐지했습니다:\n" + "\n".join(lines) + "\n"
        "(참고용 — Semgrep은 오탐이 흔한 도구이니 실제로 해당 라인의 값이 안전하게 처리되는지 "
        "직접 확인하세요.)"
    )


def build_user_prompt_grounded(source_code: str, category: str, findings: list[dict]) -> str:
    cwe = CATEGORY_TO_CWE[category]
    name = CATEGORY_TO_NAME[category]
    findings_block = build_findings_context(findings, category)
    return (
        f"다음 Java 소스 코드에 {name}(CWE-{cwe}) 취약점이 있는지 판단하세요.\n\n"
        "```java\n"
        f"{source_code}\n"
        "```\n\n"
        f"{findings_block}"
    )


def load_semgrep_findings(
    semgrep_json_path: Path, cwe_tag: str, vuln_keywords: list[str]
) -> dict[str, list[dict]]:
    """test_name -> 해당 카테고리로 판정된 finding 목록(check_id/line/message)."""
    if not semgrep_json_path.exists():
        raise FileNotFoundError(f"semgrep 결과 JSON을 찾을 수 없음: {semgrep_json_path}")

    with semgrep_json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    findings: dict[str, list[dict]] = {}
    for result in data.get("results", []):
        if not is_category_finding(result, cwe_tag, vuln_keywords):
            continue
        test_name = Path(result["path"]).stem
        findings.setdefault(test_name, []).append(
            {
                "check_id": result["check_id"],
                "line": result.get("start", {}).get("line", "?"),
                "message": result.get("extra", {}).get("message", ""),
            }
        )
    return findings


def classify_file_via_api_grounded(
    client: anthropic.Anthropic, source_code: str, category: str, findings: list[dict]
) -> tuple[VulnJudgment, dict]:
    """Claude API를 grounded 프롬프트로 호출. 반환값에 usage(토큰 수)도 포함."""
    system_prompt = build_system_prompt_grounded(category)
    user_prompt = build_user_prompt_grounded(source_code, category, findings)
    last_exc: Exception | None = None

    for attempt in range(MAX_RETRIES_PER_CALL):
        try:
            response = client.messages.parse(
                model=MODEL,
                # grounded 프롬프트는 "Semgrep 결과에 동의/반박"까지 논의하게 해서
                # ungrounded(1024로 충분)보다 reasoning이 길어짐 — 실측 1,478건 중
                # 49건(3.3%)이 1024에서 JSON 중간에 잘려 파싱 실패했음
                max_tokens=2048,
                thinking={"type": "disabled"},
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                output_format=VulnJudgment,
            )
            if response.parsed_output is None:
                raise ValueError("구조화된 출력 파싱 실패 (parsed_output=None)")
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
            return response.parsed_output, usage

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
                raise

    raise RuntimeError(f"최대 재시도 횟수({MAX_RETRIES_PER_CALL}) 초과: {last_exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument(
        "--category", default="sqli", choices=sorted(CATEGORY_TO_CWE), help="평가할 카테고리"
    )
    parser.add_argument("--sources-dir", type=Path, default=None)
    parser.add_argument(
        "--semgrep-json",
        type=Path,
        default=None,
        help="grounding에 쓸 semgrep 결과 (기본: data/results/<category>/semgrep/semgrep_results.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="결과 JSON 저장 경로 (기본: data/results/<category>/llm_grounded/llm_predictions.json)",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="이번 실행에서 새로 호출할 최대 건수(이어하기 지원)"
    )
    parser.add_argument("--mock", action="store_true")
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="기존 결과를 무시하고 전부 새로 호출 (기본은 이어하기 — 중복 과금 방지)",
    )
    args = parser.parse_args()

    sources_dir = args.sources_dir or (args.project_root / "data" / "processed" / args.category / "sources")
    semgrep_json = args.semgrep_json or (
        args.project_root / "data" / "results" / args.category / "semgrep" / "semgrep_results.json"
    )
    output_path = args.output or (
        args.project_root / "data" / "results" / args.category / "llm_grounded" / "llm_predictions.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not sources_dir.exists():
        raise FileNotFoundError(f"소스 디렉토리를 찾을 수 없음: {sources_dir}")

    cwe_tag = f"CWE-{CATEGORY_TO_CWE[args.category]}"
    vuln_keywords = CATEGORY_TO_VULN_KEYWORDS[args.category]
    findings_by_file = load_semgrep_findings(semgrep_json, cwe_tag, vuln_keywords)

    java_files = sorted(sources_dir.glob("*.java"))
    if not java_files:
        raise FileNotFoundError(f"'{sources_dir}'에 .java 파일이 없음")

    results: dict[str, dict] = {}
    if not args.no_resume and output_path.exists():
        with output_path.open(encoding="utf-8") as f:
            results = json.load(f)

    already_done = {
        name for name, r in results.items() if r.get("vulnerable") is not None and not r.get("error")
    }
    pending = [p for p in java_files if p.stem not in already_done]
    if args.limit:
        pending = pending[: args.limit]

    grand_total = len(java_files)
    print(
        f"카테고리={args.category}  전체={grand_total}  이미완료={len(already_done)}  "
        f"이번실행대상={len(pending)}"
    )
    if not pending:
        print("모두 완료되어 새로 호출할 항목이 없습니다.")
        return

    if args.mock:
        print("[MOCK MODE] 실제 Claude API를 호출하지 않습니다.\n")
        client = None
    else:
        client = anthropic.Anthropic()

    start = time.time()
    total_in = total_out = 0

    for i, path in enumerate(pending, 1):
        test_name = path.stem
        source_code = path.read_text(encoding="utf-8")
        findings = findings_by_file.get(test_name, [])

        try:
            if args.mock:
                judgment = classify_file_mock(source_code)
                usage = {"input_tokens": 0, "output_tokens": 0}
            else:
                judgment, usage = classify_file_via_api_grounded(
                    client, source_code, args.category, findings
                )
            entry = judgment.model_dump()
            entry["mock"] = args.mock
            entry["usage"] = usage
            entry["semgrep_findings_count"] = len(findings)
            results[test_name] = entry
            status = "VULNERABLE" if judgment.vulnerable else "safe"
            total_in += usage["input_tokens"]
            total_out += usage["output_tokens"]
        except Exception as e:  # noqa: BLE001
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
        remaining = avg * (len(pending) - i)
        print(f"[{i}/{len(pending)}] {test_name}: {status}  (경과 {elapsed:.0f}s, 예상 잔여 {remaining:.0f}s)")

        if i % 20 == 0 or i == len(pending):
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    n_errors = sum(1 for r in results.values() if r.get("error"))
    print(f"\n[write] {output_path} (누적 {len(results)}건, 이번 실행 {len(pending)}건, 실패 {n_errors}건)")
    if not args.mock and pending:
        # $2.00/1M input, $10.00/1M output (claude-sonnet-5)
        cost = total_in / 1_000_000 * 2.00 + total_out / 1_000_000 * 10.00
        print(
            f"[비용] 이번 실행 {len(pending)}건: 입력 {total_in:,}tok / 출력 {total_out:,}tok "
            f"→ ${cost:.4f}  (건당 평균 ${cost / len(pending):.4f})"
        )


if __name__ == "__main__":
    main()
