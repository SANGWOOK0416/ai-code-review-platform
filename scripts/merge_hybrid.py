"""
UC4: 정적분석(Semgrep) 결과와 LLM 결과를 test_name 기준으로 매칭해 신뢰도 티어로 통합한다.

통합 규칙은 --rule로 선택한다 (Ablation Study에서 두 방식을 나란히 비교하기 위해 둘 다 유지):

[cascade] (기본값) — "Semgrep이 제안하고, LLM이 검증한다"
  Semgrep이 탐지한 건에 대해서만 LLM이 재심사하는 필터 구조.
  - Semgrep 미탐지                          -> low      (predicted=False, LLM 심사 안 함)
  - Semgrep 탐지 + LLM도 취약 판정          -> high     (predicted=True)
  - Semgrep 탐지 + LLM이 '안전'을 확신       -> filtered (predicted=False, LLM이 오탐으로 기각)
  - Semgrep 탐지 + LLM 불확실/결과없음       -> medium   (predicted=True, 보수적으로 유지)

  설계 근거 (벤치마크 실측):
    1) Semgrep의 우도비는 LR+ 1.15~1.59(약함) vs LR- 0.36~0.48(강함) —
       즉 "탐지했다"보다 "탐지 안 했다"가 2~3배 정보량이 많다. 그래서 Semgrep
       미탐지를 최종 판정으로 그대로 받아들이고(low), 탐지 건만 재심사한다.
    2) Semgrep FP의 지배적 원인이 '도달 불가능한 분기'와 '상수 반환 헬퍼'인데
       (예: `(7*42)-86 > 200`이 항상 참이라 taint 대입이 죽은 코드),
       이는 상수 폴딩·도달성 판단이라 LLM이 상대적으로 잘하는 영역이다.
    3) LLM이 '안전'이라고 판단해도 confidence가 낮으면 기각하지 않는다 —
       Recall을 지키기 위해, 확신이 있을 때만 Semgrep의 경보를 뒤집는다.

[or] (기존 방식, 비교용 베이스라인)
  - 둘 다 탐지        -> high   (predicted=True)
  - 한쪽만 탐지       -> medium (predicted=True)
  - 둘 다 미탐지      -> low    (predicted=False)

입력:
  - data/results/<category>/semgrep/semgrep_predictions.csv (evaluate_semgrep.py 산출물)
  - data/results/<category>/llm/llm_predictions.json (run_llm_only_sqli.py 산출물, --mock 가능)

사용 예:
    python scripts/merge_hybrid.py --category sqli                  # 캐스케이드(기본)
    python scripts/merge_hybrid.py --category sqli --rule or        # 기존 OR 규칙
    python scripts/merge_hybrid.py --category sqli --reject-threshold 0.8
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


RULE_CASCADE = "cascade"
RULE_OR = "or"
RULES = (RULE_CASCADE, RULE_OR)

# LLM이 Semgrep의 경보를 '오탐'으로 기각하려면 이 값 이상으로 확신해야 한다.
# 잠정값 — API 키 등록 후 실제 LLM 결과가 나오면 dataset_split.py의 train 분할에서만
# 튜닝할 것 (평가에 쓰는 held-out에서 고르면 데이터 누수).
DEFAULT_REJECT_THRESHOLD = 0.70

# 최종적으로 '취약'으로 예측하는 티어 (low/filtered는 안전 예측)
PREDICTED_TIERS = frozenset({"high", "medium"})

# 티어 표시 순서 (리포트용)
TIER_ORDER = ("high", "medium", "filtered", "low")


def tier_to_predicted(tier: str) -> bool:
    """티어 -> 최종 취약 예측 여부. 규칙이 흩어지지 않게 여기 한 곳에서만 정의한다."""
    return tier in PREDICTED_TIERS


def confidence_tier_or(semgrep_detected: bool, llm_detected: bool) -> str:
    """기존 OR 규칙 — 둘 다 탐지: high, 한쪽만: medium, 둘 다 미탐지: low."""
    n_detected = int(semgrep_detected) + int(llm_detected)
    if n_detected == 2:
        return "high"
    if n_detected == 1:
        return "medium"
    return "low"


def confidence_tier_cascade(
    semgrep_detected: bool,
    llm_detected: bool,
    llm_confidence: float | None = None,
    llm_available: bool = True,
    reject_threshold: float = DEFAULT_REJECT_THRESHOLD,
) -> str:
    """캐스케이드 규칙 — Semgrep이 게이트, LLM은 그 탐지분만 재심사하는 필터.

    Semgrep이 조용하면 LLM은 아예 호출되지 않는다(low). 이는 성능 최적화가 아니라
    설계 의도다: 실측상 Semgrep의 미탐지(LR- 0.36~0.48)가 탐지(LR+ 1.15~1.59)보다
    훨씬 강한 증거이므로, 미탐지를 뒤집을 근거로 LLM 단독 판단을 쓰지 않는다.
    """
    if not semgrep_detected:
        return "low"

    if not llm_available:
        # LLM 결과 없음(API 실패 등) -> Semgrep 단독 판정으로 폴백. 놓치는 쪽보다 남기는 쪽.
        return "medium"

    if llm_detected:
        return "high"

    # 여기서부터는 LLM이 '안전'이라고 본 경우 — 확신이 충분할 때만 Semgrep을 뒤집는다.
    if llm_confidence is not None and llm_confidence >= reject_threshold:
        return "filtered"
    return "medium"


def confidence_tier(
    semgrep_detected: bool,
    llm_detected: bool,
    llm_confidence: float | None = None,
    llm_available: bool = True,
    rule: str = RULE_CASCADE,
    reject_threshold: float = DEFAULT_REJECT_THRESHOLD,
) -> str:
    """하이브리드 통합의 단일 진입점.

    app/main.py(실시간 웹훅)와 evaluate_hybrid.py 양쪽에서 이 함수를 재사용한다
    (규칙이 두 군데서 따로 구현되며 어긋나는 걸 방지).
    """
    if rule == RULE_OR:
        return confidence_tier_or(semgrep_detected, llm_detected)
    if rule == RULE_CASCADE:
        return confidence_tier_cascade(
            semgrep_detected, llm_detected, llm_confidence, llm_available, reject_threshold
        )
    raise ValueError(f"알 수 없는 통합 규칙: {rule!r} (사용 가능: {', '.join(RULES)})")


def merge(
    semgrep_preds: dict[str, dict],
    llm_preds: dict[str, dict],
    rule: str = RULE_CASCADE,
    reject_threshold: float = DEFAULT_REJECT_THRESHOLD,
) -> list[dict]:
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
        llm_confidence = lm.get("confidence") if lm is not None else None

        tier = confidence_tier(
            semgrep_detected,
            llm_detected,
            llm_confidence=llm_confidence,
            llm_available=llm_available,
            rule=rule,
            reject_threshold=reject_threshold,
        )
        predicted = tier_to_predicted(tier)

        rows.append(
            {
                "test_name": test_name,
                "ground_truth": ground_truth,
                "semgrep_detected": semgrep_detected,
                "llm_detected": llm_detected,
                "llm_available": llm_available,
                "llm_confidence": llm_confidence,
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


TIER_LABELS = {
    RULE_CASCADE: {
        "high": "High     (Semgrep 탐지 + LLM 확인)",
        "medium": "Medium   (Semgrep 탐지, LLM 불확실/없음)",
        "filtered": "Filtered (Semgrep 탐지, LLM이 오탐으로 기각)",
        "low": "Low      (Semgrep 미탐지 — LLM 미심사)",
    },
    RULE_OR: {
        "high": "High   (둘 다 탐지)",
        "medium": "Medium (한쪽만 탐지)",
        "filtered": "Filtered (해당 없음)",
        "low": "Low    (둘 다 미탐지)",
    },
}


def print_summary(rows: list[dict], category: str, rule: str, reject_threshold: float) -> None:
    tiers = {t: 0 for t in TIER_ORDER}
    n_llm_missing = 0
    n_mock = 0
    for r in rows:
        tiers[r["confidence_tier"]] += 1
        if not r["llm_available"]:
            n_llm_missing += 1
        if "[MOCK]" in (r.get("llm_reasoning") or ""):
            n_mock += 1

    labels = TIER_LABELS[rule]
    print("=" * 62)
    print(f"하이브리드 통합 결과 — {category.upper()} (Semgrep + LLM, rule={rule})")
    if rule == RULE_CASCADE:
        print(f"  LLM 기각 임계값(reject_threshold) = {reject_threshold}")
    print("=" * 62)
    print(f"  전체 케이스 : {len(rows)}")
    for tier in TIER_ORDER:
        if tier == "filtered" and rule != RULE_CASCADE:
            continue
        print(f"  {labels[tier]} : {tiers[tier]}")
    if rule == RULE_CASCADE and tiers["filtered"]:
        print(f"  -> LLM이 Semgrep 경보 {tiers['filtered']}건을 기각함 "
              f"(이 중 실제 오탐이 몇 건인지는 evaluate_hybrid.py에서 확인)")
    if n_llm_missing:
        print(f"  (참고) LLM 결과 없음/실패 : {n_llm_missing}건 — semgrep 단독 판정으로 폴백")
    if n_mock:
        print(f"  ⚠️  MOCK 응답 {n_mock}건 포함 — 이 지표는 파이프라인 검증용이며 성능 근거로 쓸 수 없음")
    print("=" * 62)


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
    parser.add_argument(
        "--rule",
        default=RULE_CASCADE,
        choices=RULES,
        help=f"통합 규칙 (기본: {RULE_CASCADE}). 'or'는 비교용 기존 베이스라인",
    )
    parser.add_argument(
        "--reject-threshold",
        type=float,
        default=DEFAULT_REJECT_THRESHOLD,
        help=(
            f"cascade 전용 — LLM이 Semgrep 경보를 기각하는 데 필요한 최소 confidence "
            f"(기본: {DEFAULT_REJECT_THRESHOLD}). train 분할에서만 튜닝할 것"
        ),
    )
    args = parser.parse_args()

    if not 0.0 <= args.reject_threshold <= 1.0:
        parser.error(f"--reject-threshold는 0.0~1.0 범위여야 함 (입력값: {args.reject_threshold})")

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

    rows = merge(semgrep_preds, llm_preds, rule=args.rule, reject_threshold=args.reject_threshold)
    write_csv(rows, output_path)
    print_summary(rows, args.category, args.rule, args.reject_threshold)
    print(f"\n[write] {output_path}")


if __name__ == "__main__":
    main()
