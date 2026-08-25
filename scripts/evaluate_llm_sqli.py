"""
LLM 단독(Claude Sonnet 5) 방식의 --category 취약점 탐지 결과(json)를
OWASP Benchmark 정답 라벨(csv)과 매칭해서 Precision/Recall/F1을 계산한다.
evaluate_semgrep.py와 동일한 패턴/출력 구조를 따름 — 두 방식을 나란히 비교하기 위함.
(과거에는 SQLi 전용이었으나 --category로 일반화함. 파일명은 하위 호환을 위해 유지)

run_llm_only_sqli.py --mock 으로 생성한 결과에도 그대로 동작한다 (파이프라인 검증용).

사용 예:
    python scripts/evaluate_llm_sqli.py --category sqli
    python scripts/evaluate_llm_sqli.py --category xss
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_semgrep import CATEGORY_TO_CWE  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


def load_ground_truth(csv_path: Path) -> dict[str, bool]:
    """test_name -> 실제 취약 여부(bool)"""
    if not csv_path.exists():
        raise FileNotFoundError(f"정답 라벨 CSV를 찾을 수 없음: {csv_path}")

    truth: dict[str, bool] = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            truth[row["test_name"]] = row["real_vulnerability"].strip().lower() == "true"
    return truth


def load_predictions(llm_json_path: Path) -> dict[str, dict]:
    """test_name -> {vulnerable, confidence, reasoning, ...}"""
    if not llm_json_path.exists():
        raise FileNotFoundError(f"LLM 결과 JSON을 찾을 수 없음: {llm_json_path}")

    with llm_json_path.open(encoding="utf-8") as f:
        return json.load(f)


def evaluate(
    truth: dict[str, bool], predictions: dict[str, dict]
) -> tuple[list[dict], dict[str, float | int]]:
    rows = []
    tp = fp = fn = tn = 0
    failed = 0  # API 호출 실패 등으로 판단 자체가 없는 케이스 (지표 계산에서 제외)

    for test_name, actual in sorted(truth.items()):
        pred = predictions.get(test_name)

        if pred is None or pred.get("vulnerable") is None:
            failed += 1
            rows.append(
                {
                    "test_name": test_name,
                    "ground_truth": actual,
                    "predicted": None,
                    "confidence": None,
                    "reasoning": (pred or {}).get("reasoning", "결과 없음 (API 호출 실패 또는 누락)"),
                }
            )
            continue

        predicted = bool(pred["vulnerable"])

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1

        rows.append(
            {
                "test_name": test_name,
                "ground_truth": actual,
                "predicted": predicted,
                "confidence": pred.get("confidence"),
                "reasoning": pred.get("reasoning", ""),
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total_evaluated = tp + fp + fn + tn
    accuracy = (tp + tn) / total_evaluated if total_evaluated else 0.0

    metrics = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "failed": failed,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total_evaluated": total_evaluated,
        "total": len(truth),
    }
    return rows, metrics


def write_predictions_csv(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["test_name", "ground_truth", "predicted", "confidence", "reasoning"]
        )
        writer.writeheader()
        writer.writerows(rows)


def write_metrics_json(metrics: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)


def print_report(metrics: dict, category: str) -> None:
    cwe = CATEGORY_TO_CWE[category]
    print("=" * 50)
    print(f"Claude Sonnet 5 단독 {category.upper()}(CWE-{cwe}) 탐지 성능")
    print("=" * 50)
    print(f"  전체 케이스     : {metrics['total']}")
    print(f"  평가 성공       : {metrics['total_evaluated']}")
    print(f"  API 실패(제외)  : {metrics['failed']}")
    print(f"  TP (진짜 취약, 탐지 O) : {metrics['tp']}")
    print(f"  FP (안전한데 오탐)     : {metrics['fp']}")
    print(f"  FN (진짜 취약인데 놓침) : {metrics['fn']}")
    print(f"  TN (안전, 탐지 안 함)   : {metrics['tn']}")
    print("-" * 50)
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1-score  : {metrics['f1']:.4f}")
    print(f"  Accuracy  : {metrics['accuracy']:.4f}")
    print("=" * 50)


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
        "--ground-truth-csv",
        type=Path,
        default=None,
        help="정답 라벨 CSV (기본: data/processed/<category>/<category>_cases.csv)",
    )
    parser.add_argument(
        "--llm-json",
        type=Path,
        default=None,
        help="LLM 결과 JSON 경로 (기본: data/results/<category>/llm/llm_predictions.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="평가 결과 저장 경로 (기본: data/results/<category>/llm)",
    )
    args = parser.parse_args()

    ground_truth_csv = args.ground_truth_csv or (
        args.project_root / "data" / "processed" / args.category / f"{args.category}_cases.csv"
    )
    llm_json = args.llm_json or (
        args.project_root / "data" / "results" / args.category / "llm" / "llm_predictions.json"
    )
    output_dir = args.output_dir or (args.project_root / "data" / "results" / args.category / "llm")

    truth = load_ground_truth(ground_truth_csv)
    predictions = load_predictions(llm_json)

    rows, metrics = evaluate(truth, predictions)

    write_predictions_csv(rows, output_dir / "llm_eval_predictions.csv")
    write_metrics_json(metrics, output_dir / "llm_metrics.json")
    print_report(metrics, args.category)
    print(f"\n[write] {output_dir / 'llm_eval_predictions.csv'}")
    print(f"[write] {output_dir / 'llm_metrics.json'}")


if __name__ == "__main__":
    main()
