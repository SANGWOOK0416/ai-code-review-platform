"""
UC4: 정적분석(Semgrep) 결과와 LLM 결과를 test_name 기준으로 매칭해 신뢰도 티어로 통합한다.

통합 규칙:
  - Semgrep과 LLM 둘 다 탐지            -> High   (predicted=True)
  - Semgrep/LLM 중 한쪽만 탐지          -> Medium (predicted=True)
  - 둘 다 미탐지(또는 LLM 결과 없음)     -> Low    (predicted=False)

입력:
  - data/results/<category>/semgrep/semgrep_predictions.csv (evaluate_semgrep.py 산출물)
  - data/results/<category>/llm/llm_predictions.json (run_llm_only_sqli.py 산출물, --mock 가능)

사용 예:
    python scripts/merge_hybrid.py --category sqli
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


def load_semgrep_predictions(csv_path: Path) -> dict[str, dict]:
    if not csv_path.exists():
        raise FileNotFoundError(
            f"semgrep 예측 CSV를 찾을 수 없음: {csv_path} "
            "(먼저 run_semgrep_scan.py + evaluate_semgrep.py를 실행해서 생성해야 함)"
        )
    result: dict[str, dict] = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            result[row["test_name"]] = {
                "ground_truth": row["ground_truth"].strip().lower() == "true",
                "detected": row["predicted"].strip().lower() == "true",
                "matched_rules": row["matched_rules"],
            }
    return result


def load_llm_predictions(json_path: Path) -> dict[str, dict]:
    if not json_path.exists():
        raise FileNotFoundError(
            f"LLM 예측 JSON을 찾을 수 없음: {json_path} "
            "(먼저 run_llm_only_sqli.py를 실행해서 생성해야 함 — API 키 없으면 --mock으로도 가능)"
        )
    with json_path.open(encoding="utf-8") as f:
        return json.load(f)


def confidence_tier(semgrep_detected: bool, llm_detected: bool) -> str:
    """하이브리드 통합의 핵심 규칙 — 둘 다 탐지: high, 한쪽만: medium, 둘 다 미탐지: low.

    app/main.py(실시간 웹훅)와 evaluate_hybrid.py 양쪽에서 동일한 규칙을 재사용하기 위해
    별도 함수로 분리함 (규칙이 두 군데서 따로 구현되며 어긋나는 걸 방지).
    """
    n_detected = int(semgrep_detected) + int(llm_detected)
    if n_detected == 2:
        return "high"
    if n_detected == 1:
        return "medium"
    return "low"


def merge(semgrep_preds: dict[str, dict], llm_preds: dict[str, dict]) -> list[dict]:
    all_names = sorted(set(semgrep_preds) | set(llm_preds))
    rows = []

    for test_name in all_names:
        sg = semgrep_preds.get(test_name)
        lm = llm_preds.get(test_name)

        ground_truth = sg["ground_truth"] if sg is not None else None
        semgrep_detected = bool(sg["detected"]) if sg is not None else False

        llm_vulnerable = lm.get("vulnerable") if lm is not None else None
        llm_available = lm is not None and llm_vulnerable is not None
        llm_detected = bool(llm_vulnerable) if llm_available else False

        tier = confidence_tier(semgrep_detected, llm_detected)
        predicted = tier in ("high", "medium")  # OR 룰: 한쪽이라도 탐지하면 취약으로 예측

        rows.append(
            {
                "test_name": test_name,
                "ground_truth": ground_truth,
                "semgrep_detected": semgrep_detected,
                "llm_detected": llm_detected,
                "llm_available": llm_available,
                "llm_confidence": lm.get("confidence") if lm is not None else None,
                "confidence_tier": tier,
                "predicted": predicted,
                "matched_rules": sg["matched_rules"] if sg is not None else "",
                "llm_reasoning": lm.get("reasoning", "") if lm is not None else "",
            }
        )

    return rows


def write_csv(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "test_name",
        "ground_truth",
        "semgrep_detected",
        "llm_detected",
        "llm_available",
        "llm_confidence",
        "confidence_tier",
        "predicted",
        "matched_rules",
        "llm_reasoning",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[dict], category: str) -> None:
    tiers = {"high": 0, "medium": 0, "low": 0}
    n_llm_missing = 0
    for r in rows:
        tiers[r["confidence_tier"]] += 1
        if not r["llm_available"]:
            n_llm_missing += 1

    print("=" * 50)
    print(f"하이브리드 통합 결과 — {category.upper()} (Semgrep + LLM)")
    print("=" * 50)
    print(f"  전체 케이스            : {len(rows)}")
    print(f"  High   (둘 다 탐지)     : {tiers['high']}")
    print(f"  Medium (한쪽만 탐지)    : {tiers['medium']}")
    print(f"  Low    (둘 다 미탐지)   : {tiers['low']}")
    if n_llm_missing:
        print(f"  (참고) LLM 결과 없음/실패 : {n_llm_missing}건 — semgrep 단독 판정으로 처리됨")
    print("=" * 50)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument("--category", default="sqli", help="병합할 카테고리 (기본: sqli)")
    parser.add_argument(
        "--semgrep-csv",
        type=Path,
        default=None,
        help="semgrep 예측 CSV 경로 (기본: data/results/<category>/semgrep/semgrep_predictions.csv)",
    )
    parser.add_argument(
        "--llm-json",
        type=Path,
        default=None,
        help="LLM 예측 JSON 경로 (기본: data/results/<category>/llm/llm_predictions.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="병합 결과 저장 경로 (기본: data/results/<category>/hybrid/hybrid_predictions.csv)",
    )
    args = parser.parse_args()

    semgrep_csv = args.semgrep_csv or (
        args.project_root / "data" / "results" / args.category / "semgrep" / "semgrep_predictions.csv"
    )
    llm_json = args.llm_json or (
        args.project_root / "data" / "results" / args.category / "llm" / "llm_predictions.json"
    )
    output_path = args.output or (
        args.project_root / "data" / "results" / args.category / "hybrid" / "hybrid_predictions.csv"
    )

    semgrep_preds = load_semgrep_predictions(semgrep_csv)
    llm_preds = load_llm_predictions(llm_json)

    rows = merge(semgrep_preds, llm_preds)
    write_csv(rows, output_path)
    print_summary(rows, args.category)
    print(f"\n[write] {output_path}")


if __name__ == "__main__":
    main()
