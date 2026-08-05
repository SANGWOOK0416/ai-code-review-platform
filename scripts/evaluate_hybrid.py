"""
merge_hybrid.py가 만든 하이브리드(Semgrep+LLM) 통합 결과의 Precision/Recall/F1을 계산한다.
evaluate_semgrep.py와 동일한 출력 패턴을 따라 Semgrep 단독/LLM 단독/하이브리드
3방식을 나란히 비교할 수 있게 함 (Ablation Study의 핵심 산출물).

사용 예:
    python scripts/evaluate_hybrid.py --category sqli
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from merge_hybrid import TIER_ORDER  # noqa: E402  (티어 정의는 merge_hybrid 한 곳에서만 관리)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


def load_hybrid_predictions(csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        raise FileNotFoundError(f"하이브리드 예측 CSV를 찾을 수 없음: {csv_path} (먼저 merge_hybrid.py를 실행)")
    with csv_path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def evaluate(rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    # 티어별로 tp/fp/fn/tn을 모두 집계한다 (예전에는 미탐지 건을 무조건 low로 넣어서,
    # cascade의 'filtered' 티어가 실제로 오탐을 걸러낸 건지 정탐을 죽인 건지 구분할 수 없었음)
    tier_breakdown: dict[str, dict[str, int]] = {}

    def bucket(tier: str) -> dict[str, int]:
        return tier_breakdown.setdefault(tier, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

    for row in rows:
        gt_raw = row["ground_truth"]
        if gt_raw not in ("True", "False"):
            continue  # ground truth 없는 케이스는 지표 계산에서 제외

        actual = gt_raw.strip().lower() == "true"
        predicted = row["predicted"].strip().lower() == "true"
        tier = row["confidence_tier"]
        b = bucket(tier)

        if actual and predicted:
            tp += 1
            b["tp"] += 1
        elif not actual and predicted:
            fp += 1
            b["fp"] += 1
        elif actual and not predicted:
            fn += 1
            b["fn"] += 1
        else:
            tn += 1
            b["tn"] += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total": total,
        "tier_breakdown": tier_breakdown,
    }


def print_report(metrics: dict, category: str) -> None:
    print("=" * 50)
    print(f"하이브리드(Semgrep+LLM) {category.upper()} 탐지 성능")
    print("=" * 50)
    print(f"  전체 케이스     : {metrics['total']}")
    print(f"  TP (진짜 취약, 탐지 O) : {metrics['tp']}")
    print(f"  FP (안전한데 오탐)     : {metrics['fp']}")
    print(f"  FN (진짜 취약인데 놓침) : {metrics['fn']}")
    print(f"  TN (안전, 탐지 안 함)   : {metrics['tn']}")
    print("-" * 50)
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1-score  : {metrics['f1']:.4f}")
    print(f"  Accuracy  : {metrics['accuracy']:.4f}")
    print("-" * 50)
    tb = metrics["tier_breakdown"]
    print("  신뢰도 티어별 분포:")
    for tier in TIER_ORDER:
        if tier not in tb:
            continue
        c = tb[tier]
        print(
            f"    {tier:<9}: TP={c['tp']:>4}  FP={c['fp']:>4}  FN={c['fn']:>4}  TN={c['tn']:>4}"
        )

    # 캐스케이드 전용 — LLM 필터가 실제로 이득이었는지 한 줄로 요약
    filt = tb.get("filtered")
    if filt:
        removed_fp = filt["tn"]   # 기각한 게 실제로 안전했다 = 오탐 제거 성공
        killed_tp = filt["fn"]    # 기각했는데 진짜 취약이었다 = 정탐 손실
        total_filtered = removed_fp + killed_tp
        print("-" * 50)
        print("  LLM 필터 효과 (cascade):")
        print(f"    Semgrep 경보 중 LLM이 기각한 건 : {total_filtered}")
        print(f"      ├ 오탐 제거 성공 (TN)         : {removed_fp}")
        print(f"      └ 정탐 손실   (FN)           : {killed_tp}")
        if total_filtered:
            print(f"    기각 정확도                    : {removed_fp / total_filtered:.4f}")
        print("    (기각 정확도가 낮으면 --reject-threshold를 올릴 것)")
    print("=" * 50)


def write_metrics_json(metrics: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument("--category", default="sqli", help="평가할 카테고리 (기본: sqli)")
    parser.add_argument(
        "--hybrid-csv",
        type=Path,
        default=None,
        help="하이브리드 예측 CSV (기본: data/results/<category>/hybrid/hybrid_predictions.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="평가 결과 저장 경로 (기본: data/results/<category>/hybrid)",
    )
    args = parser.parse_args()

    hybrid_csv = args.hybrid_csv or (
        args.project_root / "data" / "results" / args.category / "hybrid" / "hybrid_predictions.csv"
    )
    output_dir = args.output_dir or (args.project_root / "data" / "results" / args.category / "hybrid")

    rows = load_hybrid_predictions(hybrid_csv)
    metrics = evaluate(rows)

    write_metrics_json(metrics, output_dir / "hybrid_metrics.json")
    print_report(metrics, args.category)
    print(f"\n[write] {output_dir / 'hybrid_metrics.json'}")


if __name__ == "__main__":
    main()
