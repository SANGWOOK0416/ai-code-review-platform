"""
Semgrep 스캔 결과(JSON)를 OWASP Benchmark 정답 라벨(csv)과 매칭해서
Semgrep 단독 방식의 CWE 카테고리별 Precision/Recall/F1을 계산한다.
--category로 sqli(CWE-89), xss(CWE-79) 등 어떤 카테고리든 재사용 가능.

정답 라벨: data/processed/<category>/<category>_cases.csv
예측 라벨: semgrep 결과 중 해당 테스트파일에 해당 CWE 관련 finding이
          하나라도 있으면 true(취약 예측), 없으면 false로 판정.
          (p/owasp-top-ten, p/java 룰셋에는 여러 취약점 룰이 섞여 있어서,
           "이 카테고리를 탐지했는가"를 평가하려면 해당 CWE 관련 finding만
           걸러야 공정한 비교가 됨)

사용 예:
    python scripts/evaluate_semgrep.py --category sqli
    python scripts/evaluate_semgrep.py --category xss
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path, PurePosixPath

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# OWASP Benchmark category -> CWE 번호 (download_owasp_benchmark.py의 매핑과 동일)
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

# semgrep rule metadata의 cwe 필드가 비어있을 때를 대비한 vulnerability_class 보조 매칭
# (소문자로 비교, 부분 문자열 포함 여부로 판정)
CATEGORY_TO_VULN_KEYWORDS = {
    "sqli": ["sql injection"],
    "xss": ["cross-site scripting", "cross-site-scripting", "xss"],
    "cmdi": ["command injection"],
    "pathtraver": ["path traversal"],
    "crypto": ["cryptographic", "weak encryption", "insecure cipher"],
    "hash": ["insecure hash", "weak hash"],
    "weakrand": ["insecure randomness", "weak random"],
    "trustbound": ["trust boundary"],
    "securecookie": ["cookie"],
    "ldapi": ["ldap injection"],
    "xpathi": ["xpath injection"],
    "xxe": ["xml external entities", "xxe"],
}


def load_ground_truth(csv_path: Path) -> dict[str, bool]:
    """test_name -> 실제 취약 여부(bool)"""
    if not csv_path.exists():
        raise FileNotFoundError(f"정답 라벨 CSV를 찾을 수 없음: {csv_path}")

    truth: dict[str, bool] = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            truth[row["test_name"]] = row["real_vulnerability"].strip().lower() == "true"
    return truth


def semgrep_result_path(result: dict) -> PurePosixPath:
    """semgrep JSON의 path 필드를 OS 비의존적으로 파싱.

    커밋된 semgrep_results.json은 Windows 로컬에서 생성돼 절대경로가 백슬래시로
    저장되어 있다(예: C:\\Users\\...\\BenchmarkTest00024.java). 이를 Linux에서
    pathlib.Path로 읽으면 PosixPath가 백슬래시를 구분자로 인식하지 못해 경로
    전체가 하나의 파일명으로 뭉개진다(.stem/.name이 깨짐 -> test_name 매칭 실패).
    백슬래시를 슬래시로 바꾼 뒤 항상 PurePosixPath로 강제해 실행 OS와
    무관하게 동일한 결과가 나오도록 한다.
    """
    return PurePosixPath(result["path"].replace("\\", "/"))


def is_category_finding(result: dict, cwe_tag: str, vuln_keywords: list[str]) -> bool:
    meta = result.get("extra", {}).get("metadata", {})

    cwe = meta.get("cwe", [])
    if isinstance(cwe, str):
        cwe = [cwe]
    if any(cwe_tag in c for c in cwe):
        return True

    vuln_class = meta.get("vulnerability_class", [])
    if isinstance(vuln_class, str):
        vuln_class = [vuln_class]
    vuln_class_lower = [v.lower() for v in vuln_class]
    return any(keyword in v for v in vuln_class_lower for keyword in vuln_keywords)


def load_predictions(
    semgrep_json_path: Path, cwe_tag: str, vuln_keywords: list[str]
) -> dict[str, list[str]]:
    """test_name -> 해당 카테고리로 판정된 semgrep rule id 목록 (finding 있으면 예측 true)"""
    if not semgrep_json_path.exists():
        raise FileNotFoundError(f"semgrep 결과 JSON을 찾을 수 없음: {semgrep_json_path}")

    with semgrep_json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    hits: dict[str, list[str]] = {}
    for result in data.get("results", []):
        if not is_category_finding(result, cwe_tag, vuln_keywords):
            continue
        test_name = semgrep_result_path(result).stem
        hits.setdefault(test_name, []).append(result["check_id"])
    return hits


def evaluate(
    truth: dict[str, bool], predictions: dict[str, list[str]]
) -> tuple[list[dict], dict[str, float | int]]:
    rows = []
    tp = fp = fn = tn = 0

    for test_name, actual in sorted(truth.items()):
        matched_rules = predictions.get(test_name, [])
        predicted = bool(matched_rules)

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
                "matched_rules": ";".join(matched_rules),
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0

    metrics = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total": tp + fp + fn + tn,
    }
    return rows, metrics


def write_predictions_csv(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "ground_truth", "predicted", "matched_rules"])
        writer.writeheader()
        writer.writerows(rows)


def write_metrics_json(metrics: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)


def print_report(metrics: dict, category: str, cwe_tag: str) -> None:
    print("=" * 50)
    print(f"Semgrep 단독 {category.upper()}(CWE-{cwe_tag}) 탐지 성능")
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
        "--semgrep-json",
        type=Path,
        default=None,
        help="semgrep JSON 결과 경로 (기본: data/results/<category>/semgrep/semgrep_results.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="평가 결과 저장 경로 (기본: data/results/<category>/semgrep)",
    )
    args = parser.parse_args()

    cwe_tag = f"CWE-{CATEGORY_TO_CWE[args.category]}"
    vuln_keywords = CATEGORY_TO_VULN_KEYWORDS[args.category]

    ground_truth_csv = args.ground_truth_csv or (
        args.project_root / "data" / "processed" / args.category / f"{args.category}_cases.csv"
    )
    semgrep_json = args.semgrep_json or (
        args.project_root / "data" / "results" / args.category / "semgrep" / "semgrep_results.json"
    )
    output_dir = args.output_dir or (args.project_root / "data" / "results" / args.category / "semgrep")

    truth = load_ground_truth(ground_truth_csv)
    predictions = load_predictions(semgrep_json, cwe_tag, vuln_keywords)

    rows, metrics = evaluate(truth, predictions)

    write_predictions_csv(rows, output_dir / "semgrep_predictions.csv")
    write_metrics_json(metrics, output_dir / "semgrep_metrics.json")
    print_report(metrics, args.category, CATEGORY_TO_CWE[args.category])
    print(f"\n[write] {output_dir / 'semgrep_predictions.csv'}")
    print(f"[write] {output_dir / 'semgrep_metrics.json'}")


if __name__ == "__main__":
    main()
