"""
OWASP Benchmark(Java) 데이터셋을 내려받고, CWE 카테고리 하나(기본값: SQL Injection/CWE-89)에
해당하는 테스트케이스만 골라 CSV + 소스 파일로 정리하는 스크립트.

사용 예:
    python scripts/download_owasp_benchmark.py
    python scripts/download_owasp_benchmark.py --category xss --skip-clone
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from pathlib import Path

# Windows 콘솔(cp949)에서 한글 print가 깨지는 것 방지
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
EXPECTED_RESULTS_FILE = "expectedresults-1.2.csv"
TESTCODE_SUBPATH = Path("src/main/java/org/owasp/benchmark/testcode")

# OWASP Benchmark의 category 코드 -> CWE 번호 매핑 (expectedresults-1.2.csv 기준)
CATEGORY_TO_CWE = {
    "sqli": "89",
    "xss": "79",
    "cmdi": "78",
    "pathtraver": "22",
    "crypto": "327",
    "hash": "328",
    "weakrand": "330",
    "trustbound": "501",
    "securecookie": "614",
    "ldapi": "90",
    "xpathi": "643",
    "xxe": "611",
}


def clone_or_update_repo(repo_dir: Path) -> None:
    """저장소가 없으면 shallow clone, 있으면 그대로 둔다 (오프라인 반복 실행 지원)."""
    if repo_dir.exists() and any(repo_dir.iterdir()):
        print(f"[skip-clone] 이미 존재함: {repo_dir}")
        return

    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    print(f"[clone] {REPO_URL} -> {repo_dir}")
    subprocess.run(
        ["git", "clone", "--depth", "1", REPO_URL, str(repo_dir)],
        check=True,
    )


def load_expected_results(csv_path: Path) -> list[dict[str, str]]:
    """expectedresults-1.2.csv를 파싱한다.

    헤더 첫 줄이 '# test name, category, real vulnerability, cwe, Benchmark version: 1.2, ...'
    형태로 표준 CSV 헤더가 아니라서, 컬럼명을 직접 지정해서 읽는다.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"expectedresults 파일을 찾을 수 없음: {csv_path}")

    fieldnames = ["test_name", "category", "real_vulnerability", "cwe"]
    rows: list[dict[str, str]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # 헤더(주석) 줄 스킵
        for parts in reader:
            if not parts:
                continue
            row = dict(zip(fieldnames, (p.strip() for p in parts)))
            rows.append(row)
    return rows


def filter_rows(rows: list[dict[str, str]], category: str, cwe: str) -> list[dict[str, str]]:
    return [r for r in rows if r["category"] == category and r["cwe"] == cwe]


def write_filtered_csv(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "category", "real_vulnerability", "cwe"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[write] {out_path} ({len(rows)} rows)")


def copy_source_files(rows: list[dict[str, str]], repo_dir: Path, out_dir: Path) -> tuple[int, int]:
    testcode_dir = repo_dir / TESTCODE_SUBPATH
    out_dir.mkdir(parents=True, exist_ok=True)

    found, missing = 0, 0
    for row in rows:
        src = testcode_dir / f"{row['test_name']}.java"
        if src.exists():
            shutil.copy2(src, out_dir / src.name)
            found += 1
        else:
            missing += 1
    return found, missing


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--category",
        default="sqli",
        choices=sorted(CATEGORY_TO_CWE),
        help="필터링할 OWASP Benchmark 카테고리 (기본: sqli = CWE-89)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로 (기본: 이 스크립트의 상위 폴더)",
    )
    parser.add_argument("--skip-clone", action="store_true", help="이미 clone된 저장소를 재사용")
    parser.add_argument(
        "--no-copy-sources",
        action="store_true",
        help="필터링된 케이스의 .java 소스 파일 복사를 생략하고 CSV만 생성",
    )
    args = parser.parse_args()

    cwe = CATEGORY_TO_CWE[args.category]
    repo_dir = args.project_root / "data" / "raw" / "BenchmarkJava"
    processed_dir = args.project_root / "data" / "processed" / args.category

    if not args.skip_clone:
        clone_or_update_repo(repo_dir)
    elif not repo_dir.exists():
        print(f"[error] --skip-clone 지정했지만 저장소가 없음: {repo_dir}", file=sys.stderr)
        sys.exit(1)

    csv_path = repo_dir / EXPECTED_RESULTS_FILE
    all_rows = load_expected_results(csv_path)
    print(f"[parse] 전체 테스트케이스: {len(all_rows)}건")

    filtered = filter_rows(all_rows, args.category, cwe)
    n_true = sum(1 for r in filtered if r["real_vulnerability"] == "true")
    n_false = len(filtered) - n_true
    print(
        f"[filter] category={args.category} (CWE-{cwe}): {len(filtered)}건 "
        f"(취약 true={n_true} / 안전 false={n_false})"
    )

    write_filtered_csv(filtered, processed_dir / f"{args.category}_cases.csv")

    if not args.no_copy_sources:
        found, missing = copy_source_files(filtered, repo_dir, processed_dir / "sources")
        print(f"[copy] 소스 파일 복사: {found}개 성공, {missing}개 누락")
        if missing:
            print(
                "  (누락된 파일이 있으면 clone된 저장소 버전이 CSV와 다를 수 있음 — "
                "--skip-clone 없이 다시 실행해 최신 상태로 갱신 권장)"
            )


if __name__ == "__main__":
    main()
