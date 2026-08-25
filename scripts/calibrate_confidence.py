"""
LLM confidence의 보정(calibration) 상태를 측정하고, 캐스케이드의 --reject-threshold를
train 분할에서만 튜닝한다.

무엇을 보정으로 보는가 (중요):
  run_llm_only_sqli.py의 confidence는 "이 코드가 취약할 확률"이 아니라
  **"내 판정(vulnerable=True/False)이 맞을 확률"**이다. 캐스케이드도 이 값을
  "LLM이 '안전'이라고 한 판정을 믿고 Semgrep 경보를 기각할지"에 쓰므로,
  보정도 `confidence vs 판정 정확도(judgment accuracy)` 기준으로 측정한다.
    - confidence 0.9 구간의 판정이 실제로 90% 맞으면 잘 보정된 것
    - 90%보다 낮게 맞으면 과신(overconfident), 높으면 과소신(underconfident)

데이터 누수 방지:
  기본값은 --split train 이다. held-out은 최종 성능 보고 딱 한 번만 쓰기 위한
  것이므로, 튜닝/탐색 과정에서는 절대 열지 말 것. --split heldout은 의도적으로
  명시해야만 동작한다.

지표:
  ECE (Expected Calibration Error) = Σ (|구간| / N) * |구간평균confidence - 구간정확도|
  MCE (Maximum Calibration Error)  = max |구간평균confidence - 구간정확도|
  signed gap = Σ (|구간| / N) * (구간평균confidence - 구간정확도)
      → 양수면 전반적으로 과신, 음수면 과소신 (ECE는 절댓값이라 방향을 못 봄)

구간 나누기:
  --bin-mode equal-width (기본, 표준 ECE 정의와 동일: [0,0.1), [0.1,0.2), ...)
  --bin-mode quantile    (10분위 — LLM confidence가 0.85~0.99에 몰려 있어서
                          equal-width는 대부분의 구간이 비므로 실질 해상도가 높음)
  둘 다 보는 걸 권장. 표준 비교용은 equal-width, 실제 분포 파악용은 quantile.

사용 예:
    # 1) 보정 상태만 확인 (train)
    python scripts/calibrate_confidence.py --category sqli
    python scripts/calibrate_confidence.py --category sqli --bin-mode quantile

    # 2) threshold 스윕 (train)
    python scripts/calibrate_confidence.py --category sqli --sweep

    # 3) 최종 확인 — held-out에 딱 한 번만 (튜닝 끝난 뒤에!)
    python scripts/calibrate_confidence.py --category sqli --split heldout --threshold 0.7
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dataset_split import HELDOUT, TRAIN, load_split  # noqa: E402
from evaluate_semgrep import CATEGORY_TO_CWE  # noqa: E402
from merge_hybrid import (  # noqa: E402  (통합 규칙은 merge_hybrid 한 곳에서만 정의)
    DEFAULT_REJECT_THRESHOLD,
    confidence_tier_cascade,
    tier_to_predicted,
)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# threshold 스윕 후보 — LLM confidence가 상단에 몰려 있어 0.5 미만은 실질적으로
# "항상 기각"과 같으므로 촘촘하게 볼 필요가 없다.
SWEEP_CANDIDATES = [
    0.0, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.97, 0.99, 1.01
]


def load_cases(project_root: Path, category: str) -> dict[str, dict]:
    """test_name -> {ground_truth, semgrep_detected, llm_vulnerable, llm_confidence}"""
    semgrep_csv = (
        project_root / "data" / "results" / category / "semgrep" / "semgrep_predictions.csv"
    )
    llm_json = project_root / "data" / "results" / category / "llm" / "llm_predictions.json"

    if not semgrep_csv.exists():
        raise FileNotFoundError(f"semgrep 예측 CSV 없음: {semgrep_csv}")
    if not llm_json.exists():
        raise FileNotFoundError(f"LLM 예측 JSON 없음: {llm_json}")

    cases: dict[str, dict] = {}
    with semgrep_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cases[row["test_name"]] = {
                "ground_truth": row["ground_truth"].strip().lower() == "true",
                "semgrep_detected": row["predicted"].strip().lower() == "true",
                "llm_vulnerable": None,
                "llm_confidence": None,
            }

    with llm_json.open(encoding="utf-8") as f:
        llm = json.load(f)
    for name, pred in llm.items():
        if name in cases:
            cases[name]["llm_vulnerable"] = pred.get("vulnerable")
            cases[name]["llm_confidence"] = pred.get("confidence")
    return cases


def select_split(cases: dict[str, dict], split_map: dict[str, str], want: str) -> dict[str, dict]:
    return {n: c for n, c in cases.items() if split_map.get(n) == want}


# --------------------------------------------------------------------------
# 보정(calibration) 측정
# --------------------------------------------------------------------------
def make_bins(confidences: list[float], mode: str, n_bins: int) -> list[tuple[float, float]]:
    """구간 경계 리스트 [(lo, hi), ...] 생성. hi는 마지막 구간만 포함(closed)."""
    if mode == "equal-width":
        step = 1.0 / n_bins
        return [(i * step, (i + 1) * step) for i in range(n_bins)]

    # quantile: 값이 중복될 수 있으므로 중복 경계를 제거해 실제 구간 수가 줄 수 있음
    ordered = sorted(confidences)
    if not ordered:
        return []
    edges = [ordered[int(round(i * (len(ordered) - 1) / n_bins))] for i in range(n_bins + 1)]
    edges[0], edges[-1] = 0.0, 1.0
    bins = []
    for lo, hi in zip(edges, edges[1:]):
        if hi > lo:
            bins.append((lo, hi))
    return bins


def measure_calibration(cases: dict[str, dict], mode: str, n_bins: int) -> dict:
    """confidence vs 판정 정확도 비교. LLM 판단이 없는 케이스는 제외."""
    points = [
        (c["llm_confidence"], c["llm_vulnerable"] == c["ground_truth"])
        for c in cases.values()
        if c["llm_vulnerable"] is not None and c["llm_confidence"] is not None
    ]
    n = len(points)
    if n == 0:
        return {"n": 0, "ece": 0.0, "mce": 0.0, "signed_gap": 0.0, "bins": [], "overall": {}}

    bins = make_bins([p[0] for p in points], mode, n_bins)
    rows = []
    ece = signed = 0.0
    mce = 0.0

    for idx, (lo, hi) in enumerate(bins):
        is_last = idx == len(bins) - 1
        members = [
            (conf, ok)
            for conf, ok in points
            if (lo <= conf <= hi if is_last else lo <= conf < hi)
        ]
        if not members:
            rows.append({"lo": lo, "hi": hi, "count": 0, "avg_conf": None, "accuracy": None, "gap": None})
            continue
        cnt = len(members)
        avg_conf = sum(c for c, _ in members) / cnt
        acc = sum(1 for _, ok in members if ok) / cnt
        gap = avg_conf - acc
        weight = cnt / n
        ece += weight * abs(gap)
        signed += weight * gap
        mce = max(mce, abs(gap))
        rows.append(
            {"lo": lo, "hi": hi, "count": cnt, "avg_conf": avg_conf, "accuracy": acc, "gap": gap}
        )

    overall_conf = sum(c for c, _ in points) / n
    overall_acc = sum(1 for _, ok in points if ok) / n
    return {
        "n": n,
        "ece": ece,
        "mce": mce,
        "signed_gap": signed,
        "bins": rows,
        "overall": {"avg_confidence": overall_conf, "accuracy": overall_acc},
    }


def print_calibration(cal: dict, category: str, split: str, mode: str) -> None:
    print("=" * 72)
    print(f"Confidence 보정 상태 — {category.upper()} / split={split} / bins={mode}")
    print("=" * 72)
    if cal["n"] == 0:
        print("  LLM 판정이 있는 케이스가 없음")
        print("=" * 72)
        return
    o = cal["overall"]
    print(f"  대상 케이스 : {cal['n']}")
    print(f"  평균 confidence : {o['avg_confidence']:.4f}   실제 판정 정확도 : {o['accuracy']:.4f}")
    print("-" * 72)
    print(f"  {'구간':<16}{'건수':>6}{'평균conf':>11}{'정확도':>10}{'격차':>10}")
    for b in cal["bins"]:
        label = f"[{b['lo']:.2f}, {b['hi']:.2f}]"
        if b["count"] == 0:
            print(f"  {label:<16}{0:>6}{'-':>11}{'-':>10}{'-':>10}")
            continue
        print(
            f"  {label:<16}{b['count']:>6}{b['avg_conf']:>11.4f}"
            f"{b['accuracy']:>10.4f}{b['gap']:>+10.4f}"
        )
    print("-" * 72)
    print(f"  ECE (Expected Calibration Error) : {cal['ece']:.4f}")
    print(f"  MCE (Maximum  Calibration Error) : {cal['mce']:.4f}")
    tendency = "과신(overconfident)" if cal["signed_gap"] > 0 else "과소신(underconfident)"
    print(f"  signed gap                       : {cal['signed_gap']:+.4f}  → {tendency}")
    print("=" * 72)


# --------------------------------------------------------------------------
# threshold 스윕 (캐스케이드)
# --------------------------------------------------------------------------
def cascade_metrics(cases: dict[str, dict], threshold: float) -> dict:
    """주어진 reject_threshold로 캐스케이드를 적용했을 때의 지표."""
    tp = fp = fn = tn = 0
    rejected_safe = rejected_vuln = 0  # filtered 티어의 내역

    for c in cases.values():
        llm_available = c["llm_vulnerable"] is not None
        tier = confidence_tier_cascade(
            c["semgrep_detected"],
            bool(c["llm_vulnerable"]) if llm_available else False,
            c["llm_confidence"],
            llm_available,
            threshold,
        )
        predicted = tier_to_predicted(tier)
        actual = c["ground_truth"]

        if tier == "filtered":
            if actual:
                rejected_vuln += 1
            else:
                rejected_safe += 1

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    n_rejected = rejected_safe + rejected_vuln
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0,
        "rejected": n_rejected,
        "rejected_safe": rejected_safe,      # 오탐 제거 성공
        "rejected_vuln": rejected_vuln,      # 정탐 손실
        "reject_accuracy": rejected_safe / n_rejected if n_rejected else None,
    }


def sweep(cases: dict[str, dict], candidates: list[float]) -> list[dict]:
    return [cascade_metrics(cases, t) for t in candidates]


def print_sweep(results: list[dict], category: str, split: str) -> None:
    print("=" * 92)
    print(f"reject_threshold 스윕 — {category.upper()} / split={split}")
    print("  (LLM이 '안전'이라 판단할 때, confidence가 threshold 이상이어야 Semgrep 경보를 기각)")
    print("=" * 92)
    print(
        f"  {'thr':>5}{'P':>9}{'R':>9}{'F1':>9}"
        f"{'기각':>7}{'오탐제거':>9}{'정탐손실':>9}{'기각정확도':>11}"
    )
    best_f1 = max(r["f1"] for r in results)
    for r in results:
        ra = f"{r['reject_accuracy']:.4f}" if r["reject_accuracy"] is not None else "-"
        mark = "  ← F1 최대" if r["f1"] == best_f1 else ""
        print(
            f"  {r['threshold']:>5.2f}{r['precision']:>9.4f}{r['recall']:>9.4f}{r['f1']:>9.4f}"
            f"{r['rejected']:>7}{r['rejected_safe']:>9}{r['rejected_vuln']:>9}{ra:>11}{mark}"
        )
    print("=" * 92)


def pick_best(results: list[dict]) -> dict:
    """F1 최대인 threshold. 동률이면 정탐 손실이 적은 쪽, 그다음 threshold가 높은(보수적인) 쪽."""
    return sorted(results, key=lambda r: (-r["f1"], r["rejected_vuln"], -r["threshold"]))[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument(
        "--category", default="sqli", choices=sorted(CATEGORY_TO_CWE), help="대상 카테고리"
    )
    parser.add_argument(
        "--split",
        default=TRAIN,
        choices=[TRAIN, HELDOUT],
        help=f"사용할 분할 (기본: {TRAIN}). heldout은 최종 확인 1회만 쓸 것 — 튜닝에 쓰면 누수",
    )
    parser.add_argument("--bin-mode", default="equal-width", choices=["equal-width", "quantile"])
    parser.add_argument("--bins", type=int, default=10, help="구간 개수 (기본: 10)")
    parser.add_argument("--sweep", action="store_true", help="reject_threshold 스윕 수행")
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="이 threshold 하나만 평가 (최종 held-out 확인용)",
    )
    parser.add_argument("--output", type=Path, default=None, help="결과 JSON 저장 경로")
    args = parser.parse_args()

    split_map = load_split(args.project_root, args.category)
    all_cases = load_cases(args.project_root, args.category)
    cases = select_split(all_cases, split_map, args.split)
    if not cases:
        raise SystemExit(f"'{args.split}' 분할에 해당하는 케이스가 없음 (분할 파일 확인 필요)")

    if args.split == HELDOUT:
        print("!" * 72)
        print("  HELD-OUT 분할을 사용합니다 — 최종 성능 보고용입니다.")
        print("  이 결과를 보고 다시 threshold를 조정하면 데이터 누수가 됩니다.")
        print("!" * 72)
        print()

    result: dict = {"category": args.category, "split": args.split, "n_cases": len(cases)}

    if args.threshold is not None:
        m = cascade_metrics(cases, args.threshold)
        print("=" * 72)
        print(f"캐스케이드 최종 평가 — {args.category.upper()} / split={args.split} / threshold={args.threshold}")
        print("=" * 72)
        print(f"  케이스 : {len(cases)}")
        print(f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}")
        print(f"  Precision : {m['precision']:.4f}")
        print(f"  Recall    : {m['recall']:.4f}")
        print(f"  F1-score  : {m['f1']:.4f}")
        print(f"  Accuracy  : {m['accuracy']:.4f}")
        ra = f"{m['reject_accuracy']:.4f}" if m["reject_accuracy"] is not None else "-"
        print(f"  기각 {m['rejected']}건 (오탐제거 {m['rejected_safe']} / 정탐손실 {m['rejected_vuln']}), 기각정확도 {ra}")
        print("=" * 72)
        result["final"] = m
    else:
        cal = measure_calibration(cases, args.bin_mode, args.bins)
        print_calibration(cal, args.category, args.split, args.bin_mode)
        result["calibration"] = cal

        if args.sweep:
            print()
            results = sweep(cases, SWEEP_CANDIDATES)
            print_sweep(results, args.category, args.split)
            best = pick_best(results)
            print(f"\n  → F1 기준 최적 threshold = {best['threshold']:.2f} (F1={best['f1']:.4f})")
            print(f"     현재 기본값 {DEFAULT_REJECT_THRESHOLD} 대비 "
                  f"F1 {best['f1'] - cascade_metrics(cases, DEFAULT_REJECT_THRESHOLD)['f1']:+.4f}")
            result["sweep"] = results
            result["best"] = best

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[write] {args.output}")


if __name__ == "__main__":
    main()
