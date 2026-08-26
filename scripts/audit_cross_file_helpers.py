"""
"교차 파일 헬퍼 오판" 케이스에서 grounding(Semgrep 탐지 결과 제공)이 LLM의 판단을
실제로 고쳤는지 검증한다.

배경:
  이전 세션(3단계 FP 원인 분석)에서 발견한 패턴 — OWASP Benchmark 헬퍼
  `SeparateClassRequest.getTheValue()`는 요청을 무시하고 상수 "bar"를 반환하는
  안전 소스인데, 이 헬퍼의 실제 구현이 담긴 파일은 스캔 대상(sources/)에 포함되지
  않는다. LLM이 단일 파일만 보고 판단하는 한, 이 헬퍼를 쓰는 안전 케이스는 구조적으로
  오탐(FP)하기 쉽다.

  `run_llm_grounded.py`가 주는 grounding은 Semgrep의 "탐지 여부"뿐 헬퍼의 실제
  소스 코드가 아니므로, grounding이 이 오탐 부류를 고칠 수 있는지는 별개 질문이다 —
  이 스크립트가 그 질문에 실측으로 답한다.

방법:
  getTheValue() 호출이 있는 "정답=안전" 케이스를 4개 카테고리에서 전부 골라
  ungrounded(llm/llm_predictions.json) vs grounded(llm_grounded/llm_predictions.json)
  판정을 대조한다. 넷 중 하나로 분류:
    - fixed        : ungrounded 오답(True) -> grounded 정답(False)
    - still_wrong  : 양쪽 다 오답(True)
    - still_right  : 양쪽 다 정답(False)
    - regressed    : ungrounded 정답(False) -> grounded 오답(True)  (악화)

사용 예:
    python scripts/audit_cross_file_helpers.py
    python scripts/audit_cross_file_helpers.py --category sqli
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

DEFAULT_CATEGORIES = ["sqli", "xss", "cmdi", "pathtraver"]

# 안전 소스(상수 반환)인데 request 파생 객체로 오인되기 쉬운 헬퍼 호출 패턴.
# 지난 세션 FP 원인 분석에서 확인한 SeparateClassRequest.getTheValue()가 대표 사례.
HELPER_CALL_PATTERN = re.compile(r"getTheValue\s*\(")


def load_ground_truth(project_root: Path, category: str) -> dict[str, bool]:
    csv_path = project_root / "data" / "processed" / category / f"{category}_cases.csv"
    with csv_path.open(newline="", encoding="utf-8") as f:
        return {
            row["test_name"]: row["real_vulnerability"].strip().lower() == "true"
            for row in csv.DictReader(f)
        }


def load_predictions(path: Path) -> dict[str, dict]:
    if not path.exists():
        raise FileNotFoundError(f"예측 결과를 찾을 수 없음: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def classify_change(ungrounded_vuln: bool, grounded_vuln: bool) -> str:
    if ungrounded_vuln and not grounded_vuln:
        return "fixed"
    if ungrounded_vuln and grounded_vuln:
        return "still_wrong"
    if not ungrounded_vuln and not grounded_vuln:
        return "still_right"
    return "regressed"  # not ungrounded_vuln and grounded_vuln


def audit_category(project_root: Path, category: str) -> list[dict]:
    truth = load_ground_truth(project_root, category)
    src_dir = project_root / "data" / "processed" / category / "sources"
    ungrounded = load_predictions(
        project_root / "data" / "results" / category / "llm" / "llm_predictions.json"
    )
    grounded = load_predictions(
        project_root / "data" / "results" / category / "llm_grounded" / "llm_predictions.json"
    )

    rows = []
    for test_name, is_vulnerable in sorted(truth.items()):
        if is_vulnerable:
            continue  # 안전 케이스(FP 유도용)만 대상 — 이 오판 부류는 항상 FP임
        source_path = src_dir / f"{test_name}.java"
        if not source_path.exists():
            continue
        if not HELPER_CALL_PATTERN.search(source_path.read_text(encoding="utf-8", errors="replace")):
            continue

        u = ungrounded.get(test_name, {}).get("vulnerable")
        g = grounded.get(test_name, {}).get("vulnerable")
        if u is None or g is None:
            continue  # API 실패로 판정 없는 케이스는 대조에서 제외

        rows.append(
            {
                "category": category,
                "test_name": test_name,
                "ungrounded_vulnerable": u,
                "grounded_vulnerable": g,
                "change": classify_change(u, g),
                "grounded_confidence": grounded.get(test_name, {}).get("confidence"),
                "semgrep_findings_count": grounded.get(test_name, {}).get("semgrep_findings_count"),
            }
        )
    return rows


def print_report(rows: list[dict]) -> None:
    counts = {"fixed": 0, "still_wrong": 0, "still_right": 0, "regressed": 0}
    for r in rows:
        counts[r["change"]] += 1

    print("=" * 70)
    print(f"교차 파일 헬퍼 오판 대조 — 총 {len(rows)}건 (getTheValue() 사용, 정답=안전)")
    print("=" * 70)
    print(f"  고쳐짐 (ungrounded 오답 -> grounded 정답)  : {counts['fixed']}")
    print(f"  여전히 오답 (양쪽 다 틀림)                 : {counts['still_wrong']}")
    print(f"  원래 정답 (양쪽 다 맞음)                   : {counts['still_right']}")
    print(f"  악화 (ungrounded 정답 -> grounded 오답)    : {counts['regressed']}")
    print("-" * 70)
    if rows:
        fix_rate = counts["fixed"] / (counts["fixed"] + counts["still_wrong"]) if (counts["fixed"] + counts["still_wrong"]) else 0.0
        print(f"  grounding으로 인한 교정율(fixed / (fixed+still_wrong)) : {fix_rate:.4f}")
    print("=" * 70)

    regressed = [r for r in rows if r["change"] == "regressed"]
    if regressed:
        print("\n악화 사례 상세:")
        for r in regressed:
            print(
                f"  [{r['category']}/{r['test_name']}] "
                f"grounded_confidence={r['grounded_confidence']} "
                f"semgrep_findings={r['semgrep_findings_count']}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument(
        "--category",
        default=None,
        choices=DEFAULT_CATEGORIES,
        help="단일 카테고리만 (기본: 4개 카테고리 전부)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="결과 JSON 저장 경로 (기본: data/results/cross_file_helper_audit.json)",
    )
    args = parser.parse_args()

    categories = [args.category] if args.category else DEFAULT_CATEGORIES
    all_rows: list[dict] = []
    for category in categories:
        all_rows.extend(audit_category(args.project_root, category))

    print_report(all_rows)

    output_path = args.output or (args.project_root / "data" / "results" / "cross_file_helper_audit.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(all_rows, f, indent=2, ensure_ascii=False)
    print(f"\n[write] {output_path}")


if __name__ == "__main__":
    main()
