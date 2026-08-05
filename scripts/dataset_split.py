"""
OWASP Benchmark 케이스를 train / held-out으로 결정론적·층화 분할한다.

왜 필요한가 (데이터 누수 방지):
  하이브리드 통합 규칙의 하이퍼파라미터(cascade의 --reject-threshold, 향후 베이지안
  로그오즈의 카테고리별 우도비 LR, LLM confidence 보정 계수)를 평가에 쓰는 바로 그
  데이터에서 고르면, 보고된 Precision/Recall/F1이 낙관적으로 편향된다.
  → 튜닝·보정은 train에서만 하고, 최종 지표는 held-out에서만 보고할 것.

설계:
  - 결정론적: test_name의 SHA-256 해시로 배정하므로 실행할 때마다 같은 결과가 나온다.
    (파이썬 내장 hash()는 프로세스마다 salt가 달라져서 재현이 안 되므로 쓰지 않음)
  - 층화(stratified): 취약/안전 라벨별로 따로 분할해 양성 비율을 train/held-out에서
    동일하게 유지한다. (SQLi 기준 양성 비율이 약 54%인데, 분할이 치우치면
    기저율이 달라져 Precision 비교가 왜곡됨)
  - 파일 추가/삭제에 안정적: 각 케이스의 배정이 다른 케이스와 무관하게 결정되므로,
    나중에 카테고리에 케이스가 추가돼도 기존 배정이 흔들리지 않는다.

사용 예:
    python scripts/dataset_split.py --category sqli                 # 분할 생성 + 저장
    python scripts/dataset_split.py --category sqli --train-ratio 0.3
    python scripts/dataset_split.py --category sqli --dry-run       # 저장 없이 분포만 확인

다른 스크립트에서 쓸 때:
    from dataset_split import load_split, filter_by_split
    split = load_split(project_root, "sqli")
    heldout_rows = filter_by_split(rows, split, "heldout", key="test_name")
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections import Counter
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

TRAIN = "train"
HELDOUT = "heldout"
SPLITS = (TRAIN, HELDOUT)

# train 비율 기본값 — 하이퍼파라미터가 적어(임계값 1개 수준) 튜닝에 큰 표본이 필요하지
# 않고, 최종 지표의 신뢰구간을 좁히는 쪽이 더 중요해서 held-out을 크게 잡는다.
DEFAULT_TRAIN_RATIO = 0.30
DEFAULT_SEED = "capstone-2026"


def assign_split(test_name: str, train_ratio: float, seed: str = DEFAULT_SEED) -> str:
    """test_name -> 'train' 또는 'heldout' (결정론적).

    해시를 [0,1) 실수로 정규화한 뒤 train_ratio와 비교한다. seed를 바꾸면 완전히
    다른 분할이 나오므로, 한 번 정한 seed는 논문/리포트 전체에서 고정할 것.
    """
    digest = hashlib.sha256(f"{seed}:{test_name}".encode("utf-8")).digest()
    # 앞 8바이트를 정수로 -> [0,1) 구간으로 정규화
    value = int.from_bytes(digest[:8], "big") / float(1 << 64)
    return TRAIN if value < train_ratio else HELDOUT


def load_ground_truth(csv_path: Path) -> dict[str, bool]:
    """test_name -> 실제 취약 여부. evaluate_semgrep.py와 동일한 CSV 스키마를 읽는다."""
    if not csv_path.exists():
        raise FileNotFoundError(
            f"정답 라벨 CSV를 찾을 수 없음: {csv_path} "
            "(먼저 download_owasp_benchmark.py로 해당 카테고리를 수집해야 함)"
        )
    truth: dict[str, bool] = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            truth[row["test_name"]] = row["real_vulnerability"].strip().lower() == "true"
    return truth


def make_split(
    truth: dict[str, bool], train_ratio: float = DEFAULT_TRAIN_RATIO, seed: str = DEFAULT_SEED
) -> dict[str, str]:
    """층화 분할 — 취약/안전 그룹을 각각 독립적으로 나눠 양성 비율을 보존한다."""
    if not 0.0 < train_ratio < 1.0:
        raise ValueError(f"train_ratio는 0과 1 사이여야 함 (입력값: {train_ratio})")

    split: dict[str, str] = {}
    for label in (True, False):
        # 라벨별로 seed를 분리해야 층화가 실제로 동작한다.
        # (같은 seed를 쓰면 두 그룹이 같은 해시 분포를 공유해 비율이 어긋날 수 있음)
        group_seed = f"{seed}:{'vuln' if label else 'safe'}"
        for name, actual in truth.items():
            if actual is label:
                split[name] = assign_split(name, train_ratio, group_seed)
    return split


def write_split_csv(split: dict[str, str], truth: dict[str, bool], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "split", "ground_truth"])
        writer.writeheader()
        for name in sorted(split):
            writer.writerow(
                {"test_name": name, "split": split[name], "ground_truth": truth.get(name)}
            )


def load_split(project_root: Path, category: str) -> dict[str, str]:
    """저장된 분할을 읽어 test_name -> split 딕셔너리로 반환."""
    path = project_root / "data" / "processed" / category / "split.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"분할 파일이 없음: {path} "
            f"(먼저 `python scripts/dataset_split.py --category {category}` 실행)"
        )
    with path.open(newline="", encoding="utf-8") as f:
        return {row["test_name"]: row["split"] for row in csv.DictReader(f)}


def filter_by_split(
    rows: list[dict], split: dict[str, str], want: str, key: str = "test_name"
) -> list[dict]:
    """예측 결과 행들 중 지정한 split에 속한 것만 남긴다.

    분할에 없는 test_name은 제외한다 (조용히 train 취급되어 누수가 생기는 걸 막기 위해).
    """
    if want not in SPLITS:
        raise ValueError(f"split은 {SPLITS} 중 하나여야 함 (입력값: {want!r})")
    return [r for r in rows if split.get(r[key]) == want]


def print_report(split: dict[str, str], truth: dict[str, bool], category: str) -> None:
    counts: Counter[tuple[str, bool]] = Counter(
        (split[name], truth[name]) for name in split if name in truth
    )
    print("=" * 58)
    print(f"train / held-out 분할 — {category.upper()}")
    print("=" * 58)
    print(f"  {'split':<10}{'전체':>8}{'취약':>8}{'안전':>8}{'양성비율':>10}")
    for s in SPLITS:
        vuln = counts[(s, True)]
        safe = counts[(s, False)]
        total = vuln + safe
        ratio = vuln / total if total else 0.0
        print(f"  {s:<10}{total:>8}{vuln:>8}{safe:>8}{ratio:>10.1%}")
    all_vuln = counts[(TRAIN, True)] + counts[(HELDOUT, True)]
    all_total = sum(counts.values())
    print("-" * 58)
    print(f"  {'전체':<10}{all_total:>8}{all_vuln:>8}{all_total - all_vuln:>8}"
          f"{all_vuln / all_total if all_total else 0:>10.1%}")
    print("=" * 58)
    print("  ⚠️  임계값·LR·보정 계수는 train에서만 추정하고,")
    print("      최종 Precision/Recall/F1은 held-out에서만 보고할 것.")
    print("=" * 58)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument("--category", default="sqli", help="분할할 카테고리 (기본: sqli)")
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=DEFAULT_TRAIN_RATIO,
        help=f"train 비율 (기본: {DEFAULT_TRAIN_RATIO})",
    )
    parser.add_argument(
        "--seed",
        default=DEFAULT_SEED,
        help=f"분할 시드 — 한 번 정하면 고정할 것 (기본: {DEFAULT_SEED!r})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="저장 경로 (기본: data/processed/<category>/split.csv)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="파일을 저장하지 않고 분포만 출력"
    )
    args = parser.parse_args()

    truth_csv = (
        args.project_root / "data" / "processed" / args.category / f"{args.category}_cases.csv"
    )
    output_path = args.output or (
        args.project_root / "data" / "processed" / args.category / "split.csv"
    )

    truth = load_ground_truth(truth_csv)
    split = make_split(truth, args.train_ratio, args.seed)
    print_report(split, truth, args.category)

    if args.dry_run:
        print("\n[dry-run] 저장하지 않음")
        return

    write_split_csv(split, truth, output_path)
    print(f"\n[write] {output_path}")


if __name__ == "__main__":
    main()
