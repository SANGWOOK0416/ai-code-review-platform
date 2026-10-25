"""
Semgrep으로 OWASP Benchmark SQLi 소스 파일들을 정적분석하고 결과를 JSON/SARIF로 저장한다.

사용 예:
    python scripts/run_semgrep_scan.py
    python scripts/run_semgrep_scan.py --sources-dir data/processed/xss/sources --category xss
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

DEFAULT_CONFIGS = ["p/java", "p/owasp-top-ten"]
DEFAULT_FORMATS = ["json", "sarif"]


class SemgrepError(RuntimeError):
    """semgrep 실행 실패 (비정상 종료 코드)."""


class SemgrepTimeout(SemgrepError):
    """semgrep이 제한 시간 안에 끝나지 않아 프로세스 트리를 종료함."""


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """semgrep(파이썬 래퍼)이 띄운 semgrep-core까지 함께 종료한다."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.kill()


def run_with_timeout(cmd: list, env: dict, timeout: float | None) -> subprocess.CompletedProcess:
    """subprocess.run과 같지만, 타임아웃 시 자식 프로세스까지 정리하고 SemgrepTimeout을 낸다."""
    group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(
        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", **group
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc)
        proc.communicate()
        raise SemgrepTimeout(f"semgrep이 {timeout:.0f}초 안에 끝나지 않아 종료함") from None
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def run_semgrep(
    sources_dir: Path,
    output_dir: Path,
    configs: list[str],
    formats: list[str],
    timeout: float | None = None,
) -> dict[str, Path]:
    """timeout(초)을 주면 포맷별 실행마다 그 시간을 넘길 때 SemgrepTimeout. 기본은 제한 없음(배치용)."""
    if not sources_dir.exists():
        raise FileNotFoundError(f"소스 디렉토리를 찾을 수 없음: {sources_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Windows(cp949) 콘솔 환경에서 SARIF/JSON 결과에 포함된 유니코드 문자(이모지 등)를
    # 파일에 쓰다가 UnicodeEncodeError로 죽는 걸 방지 (semgrep이 로케일 기본 인코딩을 씀)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    out_paths: dict[str, Path] = {}
    for fmt in formats:
        out_path = output_dir / f"semgrep_results.{fmt}"
        cmd = ["semgrep", "scan"]
        for c in configs:
            cmd += ["--config", c]
        cmd += [f"--{fmt}", "-o", str(out_path), "--metrics=off", str(sources_dir)]

        print(f"[semgrep] {fmt} 스캔 시작: config={configs}")
        start = time.time()
        proc = run_with_timeout(cmd, env, timeout)
        elapsed = time.time() - start

        # semgrep은 스캔 자체가 정상 완료돼도 finding 유무에 따라 0 또는 1을 반환할 수 있음.
        # 그 외 코드는 실제 실행 실패로 간주.
        if proc.returncode not in (0, 1):
            print(proc.stdout, file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            raise SemgrepError(f"semgrep이 {fmt} 포맷에서 exit code {proc.returncode}로 종료됨")

        print(f"[semgrep] {fmt} 완료 ({elapsed:.1f}s) -> {out_path}")
        out_paths[fmt] = out_path

    return out_paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="프로젝트 루트 경로",
    )
    parser.add_argument("--category", default="sqli", help="결과 저장 폴더명에 쓰일 카테고리 (기본: sqli)")
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=None,
        help="스캔할 .java 소스 디렉토리 (기본: data/processed/<category>/sources)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="결과 저장 디렉토리 (기본: data/results/<category>/semgrep)",
    )
    parser.add_argument(
        "--config",
        action="append",
        dest="configs",
        default=None,
        help="semgrep --config 값 (여러 번 지정 가능, 기본: p/java, p/owasp-top-ten)",
    )
    parser.add_argument(
        "--format",
        action="append",
        dest="formats",
        default=None,
        choices=["json", "sarif"],
        help="출력 포맷 (여러 번 지정 가능, 기본: json, sarif)",
    )
    args = parser.parse_args()

    sources_dir = args.sources_dir or (args.project_root / "data" / "processed" / args.category / "sources")
    output_dir = args.output_dir or (args.project_root / "data" / "results" / args.category / "semgrep")
    configs = args.configs or DEFAULT_CONFIGS
    formats = args.formats or DEFAULT_FORMATS

    run_semgrep(sources_dir, output_dir, configs, formats)


if __name__ == "__main__":
    main()
