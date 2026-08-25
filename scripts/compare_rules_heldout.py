"""
held-out 분할에서 4방식(Semgrep 단독 / LLM 단독 / 하이브리드 OR / 하이브리드 cascade)을
나란히 비교한다 — Ablation Study의 최종 산출물.

왜 held-out인가:
  전체 데이터로 계산한 지표는 threshold 튜닝에 쓴 train이 섞여 있어 낙관적으로
  편향된다. 통합 규칙 비교는 튜닝에 쓰지 않은 held-out에서만 보고해야 방어 가능하다.
  (train/held-out 분할은 dataset_split.py의 결정론적 층화 분할)

공정성 참고:
  cascade는 --reject-threshold를 train에서 튜닝했고, OR은 튜닝할 하이퍼파라미터가
  없다. 즉 cascade 쪽에만 튜닝 기회가 있었던 셈인데, 실측상 threshold 튜닝의
  실익이 0이었으므로(F1 최대 구간이 넓어 기본값 0.7도 최적 구간 안) 이 비대칭이
  결과를 왜곡하지는 않는다. 자세한 근거는 CLAUDE.md "Confidence 보정 및
  threshold 튜닝 결과" 참고.

사용 예:
    python scripts/compare_rules_heldout.py                    # 4개 카테고리 전부
    python scripts/compare_rules_heldout.py --category sqli
    python scripts/compare_rules_heldout.py --split train      # (참고용) train에서 비교
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_confidence import load_cases, select_split  # noqa: E402
from dataset_split import HELDOUT, TRAIN, load_split  # noqa: E402
from evaluate_semgrep import CATEGORY_TO_CWE  # noqa: E402
from merge_hybrid import (  # noqa: E402
    confidence_tier_cascade,
    confidence_tier_or,
    tier_to_predicted,
)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

DEFAULT_CATEGORIES = ["sqli", "xss", "cmdi", "pathtraver"]

# calibrate_confidence.py --sweep 으로 **train 분할에서만** 고른 값.
# (F1 최대 구간이 0.00부터 넓게 형성되어 실익은 없었고, 동률 구간에서 가장
#  보수적인 = 높은 값을 선택한 결과. 자세한 근거는 CLAUDE.md 참고)
TUNED_THRESHOLDS = {
    "sqli": 0.85,
    "xss": 0.80,
    "cmdi": 0.75,
    "pathtraver": 0.85,
}


def _score(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total = tp + fp + fn + tn
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / total if total else 0.0,
        "total": total,
    }


def _tally(cases: dict[str, dict], predict) -> dict:
    """predict(case) -> bool 로 예측을 만들고 TP/FP/FN/TN을 센다."""
    tp = fp = fn = tn = 0
    for c in cases.values():
        actual = c["ground_truth"]
        predicted = predict(c)
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1
    return _score(tp, fp, fn, tn)


def evaluate_all_rules(cases: dict[str, dict], threshold: float) -> dict[str, dict]:
    """네 방식을 같은 케이스 집합에 적용한 결과."""

    def semgrep_only(c: dict) -> bool:
        return c["semgrep_detected"]

    def llm_only(c: dict) -> bool:
        # LLM 판정이 없는 케이스(API 실패)는 '탐지 안 함'으로 보수 처리
        return bool(c["llm_vulnerable"]) if c["llm_vulnerable"] is not None else False

    def hybrid_or(c: dict) -> bool:
        return tier_to_predicted(
            confidence_tier_or(c["semgrep_detected"], llm_only(c))
        )

    def hybrid_cascade(c: dict) -> bool:
        available = c["llm_vulnerable"] is not None
        return tier_to_predicted(
            confidence_tier_cascade(
                c["semgrep_detected"], llm_only(c), c["llm_confidence"], available, threshold
            )
        )

    return {
        "semgrep_only": _tally(cases, semgrep_only),
        "llm_only": _tally(cases, llm_only),
        "hybrid_or": _tally(cases, hybrid_or),
        "hybrid_cascade": _tally(cases, hybrid_cascade),
    }


RULE_LABELS = {
    "semgrep_only": "Semgrep 단독",
    "llm_only": "LLM 단독",
    "hybrid_or": "하이브리드 (OR)",
    "hybrid_cascade": "하이브리드 (cascade)",
}


def print_category(category: str, threshold: float, n: int, results: dict[str, dict]) -> None:
    print("=" * 84)
    print(f"[{category.upper()}] held-out {n}건 — cascade threshold={threshold}")
    print("=" * 84)
    print(f"  {'방식':<24}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'Precision':>11}{'Recall':>9}{'F1':>9}")
    best_f1 = max(r["f1"] for r in results.values())
    for key in ("semgrep_only", "llm_only", "hybrid_or", "hybrid_cascade"):
        r = results[key]
        mark = "  ←최고" if r["f1"] == best_f1 else ""
        print(
            f"  {RULE_LABELS[key]:<24}{r['tp']:>5}{r['fp']:>5}{r['fn']:>5}{r['tn']:>5}"
            f"{r['precision']:>11.4f}{r['recall']:>9.4f}{r['f1']:>9.4f}{mark}"
        )
    o, c = results["hybrid_or"], results["hybrid_cascade"]
    print("-" * 84)
    print(
        f"  OR → cascade 변화 : Precision {c['precision'] - o['precision']:+.4f}, "
        f"Recall {c['recall'] - o['recall']:+.4f}, F1 {c['f1'] - o['f1']:+.4f}"
    )
    print("=" * 84)


def print_summary(all_results: dict[str, dict]) -> None:
    print()
    print("=" * 84)
    print("종합 — held-out F1 (4방식 × 카테고리)")
    print("=" * 84)
    print(f"  {'카테고리':<14}{'Semgrep':>11}{'LLM단독':>11}{'OR':>11}{'cascade':>11}{'OR→cascade':>13}")
    for category, payload in all_results.items():
        r = payload["results"]
        delta = r["hybrid_cascade"]["f1"] - r["hybrid_or"]["f1"]
        print(
            f"  {category:<14}{r['semgrep_only']['f1']:>11.4f}{r['llm_only']['f1']:>11.4f}"
            f"{r['hybrid_or']['f1']:>11.4f}{r['hybrid_cascade']['f1']:>11.4f}{delta:>+13.4f}"
        )
    print("-" * 84)
    print(f"  {'평균':<14}", end="")
    for key in ("semgrep_only", "llm_only", "hybrid_or", "hybrid_cascade"):
        avg = sum(p["results"][key]["f1"] for p in all_results.values()) / len(all_results)
        print(f"{avg:>11.4f}", end="")
    avg_delta = sum(
        p["results"]["hybrid_cascade"]["f1"] - p["results"]["hybrid_or"]["f1"]
        for p in all_results.values()
    ) / len(all_results)
    print(f"{avg_delta:>+13.4f}")
    print("=" * 84)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument(
        "--category",
        default=None,
        choices=sorted(CATEGORY_TO_CWE),
        help="단일 카테고리만 (기본: sqli/xss/cmdi/pathtraver 전부)",
    )
    parser.add_argument(
        "--split",
        default=HELDOUT,
        choices=[TRAIN, HELDOUT],
        help=f"사용할 분할 (기본: {HELDOUT} — 규칙 비교는 held-out에서 보고해야 함)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="cascade threshold를 이 값으로 통일 (기본: 카테고리별 튜닝값)",
    )
    parser.add_argument("--output", type=Path, default=None, help="결과 JSON 저장 경로")
    args = parser.parse_args()

    categories = [args.category] if args.category else DEFAULT_CATEGORIES
    all_results: dict[str, dict] = {}

    for category in categories:
        split_map = load_split(args.project_root, category)
        cases = select_split(load_cases(args.project_root, category), split_map, args.split)
        if not cases:
            print(f"[skip] {category}: '{args.split}' 분할에 케이스 없음", file=sys.stderr)
            continue
        threshold = (
            args.threshold
            if args.threshold is not None
            else TUNED_THRESHOLDS.get(category, 0.70)
        )
        results = evaluate_all_rules(cases, threshold)
        print_category(category, threshold, len(cases), results)
        print()
        all_results[category] = {
            "n_cases": len(cases),
            "threshold": threshold,
            "results": results,
        }

    if len(all_results) > 1:
        print_summary(all_results)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as f:
            json.dump({"split": args.split, "categories": all_results}, f, indent=2, ensure_ascii=False)
        print(f"\n[write] {args.output}")


if __name__ == "__main__":
    main()
