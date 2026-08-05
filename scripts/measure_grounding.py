"""
LLM의 reasoning이 '실제로 존재하는 코드'를 근거로 들었는지 검증해 환각률을 측정한다.

왜 필요한가:
  이 프로젝트의 핵심 기여 주장은 "정적분석 결과를 grounding 컨텍스트로 제공하면
  LLM의 환각이 억제된다"인데, Precision/Recall/F1만으로는 이 주장을 증명할 수 없다
  (정답을 맞혔어도 근거가 날조된 것일 수 있음). reasoning에서 인용한 라인 번호·변수명·
  메서드명이 원본 파일에 실제로 존재하는지 대조하면, 그 주장을 정량 지표로 만들 수 있다.

측정 방식:
  reasoning 텍스트에서 '검증 가능한 인용'을 추출해 원본 .java 파일과 대조한다.

    [line]   "24번째 줄", "line 24", "L24"    -> 파일 라인 수 범위 안이고 빈 줄이 아닌가
    [ident]  백틱으로 감싼 코드, 변수명        -> 소스의 식별자 토큰에 존재하는가
    [call]   executeQuery(, getParameter(     -> 소스에 해당 호출이 존재하는가
    [type]   PreparedStatement, HttpServlet   -> 소스에 존재하는가 (보조 지표, 아래 주의)

  ⚠️ 권고문 제외: "PreparedStatement를 썼어야 함"처럼 '코드에 없는 것을 제안하는' 문장은
     코드에 대한 주장이 아니므로 인용으로 세지 않는다. 이걸 걸러내지 않으면 올바른
     보안 권고가 전부 환각으로 잘못 집계된다. (RECOMMENDATION_MARKERS 참고)

  ⚠️ [type]은 권고문 필터를 통과해도 여전히 오염되기 쉬워(일반론 언급이 잦음)
     기본 종합 지표에서 제외하고 따로 보고한다. --include-types로 포함 가능.

지표:
  grounding precision = 검증된 인용 수 / 전체 인용 수
  hallucination rate  = 1 - grounding precision
  (인용이 0건인 응답은 '근거 미제시'로 따로 집계 — 정밀도 계산에서는 제외)

사용 예:
    # LLM 단독(grounding 미제공) 단일 측정
    python scripts/measure_grounding.py --category sqli

    # 두 arm 비교: LLM 단독 vs 하이브리드(grounding 제공)
    python scripts/measure_grounding.py --category sqli \
        --compare-json data/results/sqli/llm_grounded/llm_predictions.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# --------------------------------------------------------------------------
# 인용 추출 패턴
# --------------------------------------------------------------------------

# "24번째 줄", "24행", "24번 라인", "line 24", "L24"
LINE_PATTERNS = [
    re.compile(r"(\d+)\s*(?:번째|번)?\s*(?:줄|행|라인)"),
    re.compile(r"\bline\s*#?\s*(\d+)", re.IGNORECASE),
    re.compile(r"\bL(\d{1,4})\b"),
]

# 백틱으로 감싼 코드 조각 — 프롬프트가 구체적 근거를 요구하므로 신호가 가장 강함
BACKTICK_PATTERN = re.compile(r"`([^`\n]{1,80})`")

# 메서드 호출: foo( 또는 obj.foo(
CALL_PATTERN = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")

# CamelCase 타입명: PreparedStatement, HttpServletRequest 등
TYPE_PATTERN = re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+)\b")

# 자바 식별자 토큰 (소스 쪽 인덱싱용)
JAVA_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# 권고/가정 문맥 — 이 표현이 있는 문장의 인용은 '코드에 대한 주장'이 아니므로 제외
RECOMMENDATION_MARKERS = (
    "해야", "했어야", "썼어야", "쓰는 것이", "사용하는 것이", "권장", "권고", "필요합니다",
    "바꾸", "교체", "대신", "개선", "수정", "방어", "예방", "권한다", "좋습니다", "합니다만",
    "should", "recommend", "instead", "must be", "consider", "could be", "would be",
    "if it were", "가정", "예를 들",
)

# 코드 인용이 아니라 일반 용어로 흔히 쓰이는 단어 — 인용 집계에서 제외
STOPWORDS = {
    # 보안/일반 용어
    "sql", "injection", "xss", "cwe", "owasp", "http", "https", "api", "url", "uri",
    "json", "html", "java", "javascript", "database", "db", "query", "input", "output",
    "user", "attack", "attacker", "payload", "sanitize", "sanitizer", "escape",
    "vulnerability", "vulnerable", "safe", "unsafe", "true", "false", "null", "none",
    # 자바 예약어/제어 구문 (호출 패턴에 걸리지만 인용으로 볼 수 없음)
    "if", "for", "while", "switch", "catch", "return", "new", "throw", "try",
    "do", "else", "synchronized", "super", "this", "assert",
}


def split_sentences(text: str) -> list[str]:
    """문장 단위 분리 — 권고문 판정을 문장 범위로 한정하기 위함."""
    parts = re.split(r"(?<=[.!?])\s+|[\n\r]+|(?<=다)\s+(?=[A-Z가-힣])", text)
    return [p.strip() for p in parts if p and p.strip()]


def is_recommendation(sentence: str) -> bool:
    low = sentence.lower()
    return any(m in sentence or m in low for m in RECOMMENDATION_MARKERS)


def index_source(source_code: str) -> tuple[set[str], list[str]]:
    """소스에서 (식별자 토큰 집합, 라인 리스트)를 만든다."""
    tokens = {t for t in JAVA_TOKEN.findall(source_code)}
    lines = source_code.splitlines()
    return tokens, lines


def _line_is_substantive(lines: list[str], n: int) -> bool:
    """인용된 라인이 실제 코드 라인인지 (빈 줄·순수 주석이면 근거로 약하다)."""
    if not 1 <= n <= len(lines):
        return False
    stripped = lines[n - 1].strip()
    if not stripped:
        return False
    return not stripped.startswith(("//", "*", "/*"))


def extract_citations(reasoning: str, include_types: bool) -> list[tuple[str, str]]:
    """reasoning -> [(종류, 값), ...] 인용 목록. 권고문 문장은 건너뛴다."""
    citations: list[tuple[str, str]] = []

    for sentence in split_sentences(reasoning):
        if is_recommendation(sentence):
            continue

        for pat in LINE_PATTERNS:
            for m in pat.finditer(sentence):
                citations.append(("line", m.group(1)))

        # 백틱 안의 내용에서 식별자만 뽑는다 (`request.getParameter("x")` -> request, getParameter)
        for m in BACKTICK_PATTERN.finditer(sentence):
            for tok in JAVA_TOKEN.findall(m.group(1)):
                if tok.lower() not in STOPWORDS and len(tok) > 2:
                    citations.append(("ident", tok))

        for m in CALL_PATTERN.finditer(sentence):
            name = m.group(1)
            if name.lower() not in STOPWORDS and len(name) > 2:
                citations.append(("call", name))

        if include_types:
            for m in TYPE_PATTERN.finditer(sentence):
                name = m.group(1)
                if name.lower() not in STOPWORDS:
                    citations.append(("type", name))

    # 중복 제거 (같은 근거를 여러 번 말했다고 가중치를 주지 않음)
    return sorted(set(citations))


def verify_citation(kind: str, value: str, tokens: set[str], lines: list[str]) -> bool:
    if kind == "line":
        try:
            return _line_is_substantive(lines, int(value))
        except ValueError:
            return False
    return value in tokens


def measure(
    predictions: dict[str, dict], sources_dir: Path, include_types: bool
) -> dict:
    per_kind: dict[str, dict[str, int]] = {}
    total = verified = 0
    n_cases = n_no_citation = n_skipped = n_mock = 0
    hallucinated_examples: list[tuple[str, str, str]] = []

    for test_name, pred in sorted(predictions.items()):
        reasoning = (pred or {}).get("reasoning") or ""
        if pred.get("error") or not reasoning:
            n_skipped += 1
            continue
        if "[MOCK]" in reasoning:
            n_mock += 1

        source_path = sources_dir / f"{test_name}.java"
        if not source_path.exists():
            n_skipped += 1
            continue

        tokens, lines = index_source(source_path.read_text(encoding="utf-8", errors="replace"))
        citations = extract_citations(reasoning, include_types)
        n_cases += 1

        if not citations:
            n_no_citation += 1
            continue

        for kind, value in citations:
            ok = verify_citation(kind, value, tokens, lines)
            bucket = per_kind.setdefault(kind, {"total": 0, "verified": 0})
            bucket["total"] += 1
            total += 1
            if ok:
                bucket["verified"] += 1
                verified += 1
            elif len(hallucinated_examples) < 10:
                hallucinated_examples.append((test_name, kind, value))

    precision = verified / total if total else 0.0
    return {
        "n_cases_with_reasoning": n_cases,
        "n_no_citation": n_no_citation,
        "n_skipped": n_skipped,
        "n_mock": n_mock,
        "citations_total": total,
        "citations_verified": verified,
        "grounding_precision": precision,
        "hallucination_rate": 1.0 - precision if total else 0.0,
        "per_kind": per_kind,
        "hallucinated_examples": hallucinated_examples,
    }


def print_report(m: dict, label: str) -> None:
    print("=" * 62)
    print(f"Grounding 측정 — {label}")
    print("=" * 62)
    print(f"  reasoning 있는 케이스 : {m['n_cases_with_reasoning']}")
    print(f"  인용 0건(근거 미제시) : {m['n_no_citation']}")
    if m["n_skipped"]:
        print(f"  제외(오류/소스없음)   : {m['n_skipped']}")
    print("-" * 62)
    print(f"  전체 인용   : {m['citations_total']}")
    print(f"  검증 성공   : {m['citations_verified']}")
    print(f"  Grounding precision : {m['grounding_precision']:.4f}")
    print(f"  환각률(hallucination) : {m['hallucination_rate']:.4f}")
    if m["per_kind"]:
        print("-" * 62)
        print("  인용 종류별:")
        for kind in ("line", "ident", "call", "type"):
            b = m["per_kind"].get(kind)
            if not b:
                continue
            p = b["verified"] / b["total"] if b["total"] else 0.0
            print(f"    {kind:<6}: {b['verified']:>5}/{b['total']:<5} precision={p:.4f}")
    if m["hallucinated_examples"]:
        print("-" * 62)
        print("  검증 실패 예시 (존재하지 않는 근거):")
        for name, kind, value in m["hallucinated_examples"]:
            print(f"    {name}  [{kind}] {value}")
    if m["n_mock"]:
        print("-" * 62)
        print(f"  ⚠️  MOCK 응답 {m['n_mock']}건 — mock reasoning에는 실제 근거가 없으므로")
        print("      이 수치는 스크립트 동작 확인용일 뿐 환각률 근거로 쓸 수 없음.")
    print("=" * 62)


def print_comparison(base: dict, comp: dict, base_label: str, comp_label: str) -> None:
    print()
    print("=" * 62)
    print("Arm 비교 — grounding 제공이 환각을 줄였는가")
    print("=" * 62)
    print(f"  {'지표':<24}{base_label:>17}{comp_label:>17}")
    rows = [
        ("Grounding precision", "grounding_precision", True),
        ("환각률", "hallucination_rate", True),
        ("전체 인용 수", "citations_total", False),
        ("근거 미제시 케이스", "n_no_citation", False),
    ]
    for label, key, is_ratio in rows:
        b, c = base[key], comp[key]
        bs = f"{b:.4f}" if is_ratio else str(b)
        cs = f"{c:.4f}" if is_ratio else str(c)
        print(f"  {label:<24}{bs:>17}{cs:>17}")
    delta = comp["hallucination_rate"] - base["hallucination_rate"]
    print("-" * 62)
    if delta < 0:
        print(f"  → grounding 제공 시 환각률 {abs(delta):.4f} 감소 (핵심 주장과 부합)")
    elif delta > 0:
        print(f"  → grounding 제공 시 환각률 {delta:.4f} 증가 (주장과 반대 — 원인 분석 필요)")
    else:
        print("  → 차이 없음")
    print("=" * 62)


def load_predictions(path: Path) -> dict[str, dict]:
    if not path.exists():
        raise FileNotFoundError(f"LLM 예측 JSON을 찾을 수 없음: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument("--category", default="sqli", help="측정할 카테고리 (기본: sqli)")
    parser.add_argument(
        "--llm-json",
        type=Path,
        default=None,
        help="기준 arm의 LLM 결과 (기본: data/results/<category>/llm/llm_predictions.json)",
    )
    parser.add_argument(
        "--compare-json",
        type=Path,
        default=None,
        help="비교 arm의 LLM 결과 — grounding을 제공해서 얻은 결과 JSON",
    )
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=None,
        help="원본 소스 디렉토리 (기본: data/processed/<category>/sources)",
    )
    parser.add_argument(
        "--include-types",
        action="store_true",
        help="CamelCase 타입명 인용도 종합 지표에 포함 (기본: 제외, 오염되기 쉬움)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="측정 결과 JSON 저장 경로 (기본: data/results/<category>/grounding/grounding_metrics.json)",
    )
    args = parser.parse_args()

    sources_dir = args.sources_dir or (
        args.project_root / "data" / "processed" / args.category / "sources"
    )
    base_json = args.llm_json or (
        args.project_root / "data" / "results" / args.category / "llm" / "llm_predictions.json"
    )
    output_path = args.output or (
        args.project_root
        / "data"
        / "results"
        / args.category
        / "grounding"
        / "grounding_metrics.json"
    )

    if not sources_dir.exists():
        raise FileNotFoundError(f"소스 디렉토리를 찾을 수 없음: {sources_dir}")

    base = measure(load_predictions(base_json), sources_dir, args.include_types)
    print_report(base, f"{args.category.upper()} / LLM 단독 (grounding 미제공)")

    result = {"category": args.category, "baseline": base}

    if args.compare_json:
        comp = measure(load_predictions(args.compare_json), sources_dir, args.include_types)
        print_report(comp, f"{args.category.upper()} / 하이브리드 (grounding 제공)")
        print_comparison(base, comp, "grounding 없음", "grounding 있음")
        result["grounded"] = comp
    else:
        print()
        print("[안내] --compare-json이 지정되지 않아 단일 arm만 측정했습니다.")
        print("      비교하려면 Semgrep 결과를 프롬프트에 넣어 실행한 LLM 결과 JSON이 필요합니다")
        print("      (현재 run_llm_only_sqli.py는 의도적으로 grounding을 제공하지 않으므로,")
        print("       grounded 버전 실행 경로를 따로 만들어야 합니다).")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[write] {output_path}")


if __name__ == "__main__":
    main()
