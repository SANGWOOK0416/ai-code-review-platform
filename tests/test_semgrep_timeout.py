"""단위 테스트 — Semgrep 실행 타임아웃 (scripts/run_semgrep_scan.py)과 preflight의 semgrep.dev 확인.

semgrep 대신 파이썬 하위 프로세스로 실제 타임아웃·프로세스 종료를 재현한다.
"""
import os
import subprocess
import sys
import time

import pytest

import demo_preflight
import run_semgrep_scan
from run_semgrep_scan import SemgrepError, SemgrepTimeout, run_with_timeout


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_normal_command_completes_within_timeout():
    """B25: 제한 시간 안에 끝나는 명령은 종료 코드와 출력을 그대로 돌려준다."""
    result = run_with_timeout([sys.executable, "-c", "print('ok')"], dict(os.environ), timeout=30)
    assert result.returncode == 0 and result.stdout.strip() == "ok"


def test_slow_command_raises_timeout_quickly():
    """B25: 제한 시간을 넘기면 기다리지 않고 SemgrepTimeout을 낸다 (SemgrepError의 하위 클래스)."""
    started = time.monotonic()
    with pytest.raises(SemgrepTimeout):
        run_with_timeout([sys.executable, "-c", "import time; time.sleep(60)"], dict(os.environ), timeout=1)
    assert time.monotonic() - started < 15
    assert issubclass(SemgrepTimeout, SemgrepError)


def test_timeout_kills_grandchild_process(tmp_path):
    """B26: 타임아웃 시 semgrep이 띄우는 semgrep-core 같은 손자 프로세스까지 함께 종료한다."""
    pid_file = tmp_path / "grandchild.pid"
    parent_code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open(r'{pid_file}', 'w').write(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    with pytest.raises(SemgrepTimeout):
        run_with_timeout([sys.executable, "-c", parent_code], dict(os.environ), timeout=3)
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while pid_alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not pid_alive(grandchild)


def test_run_semgrep_passes_timeout_and_raises_on_bad_exit(monkeypatch, tmp_path):
    """B27: run_semgrep은 timeout을 실행 함수에 넘기고, 비정상 종료 코드(2)는 SemgrepError로 낸다."""
    seen = {}

    def fake_run(cmd, env, timeout):
        seen["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, 2, "", "Failed to download configuration")

    monkeypatch.setattr(run_semgrep_scan, "run_with_timeout", fake_run)
    (tmp_path / "src").mkdir()
    with pytest.raises(SemgrepError, match="exit code 2"):
        run_semgrep_scan.run_semgrep(tmp_path / "src", tmp_path / "out", ["p/java"], ["json"], timeout=90)
    assert seen["timeout"] == 90


@pytest.mark.parametrize(
    "status, expected",
    [(200, "OK"), (403, "FAIL"), (None, "FAIL")],
)
def test_preflight_semgrep_registry_check(monkeypatch, status, expected):
    """B28: preflight의 semgrep.dev 접속 항목 — 200이면 OK, 그 외 응답이나 연결 실패면 FAIL."""
    monkeypatch.setattr(demo_preflight, "http", lambda method, url, **kw: (status, "" if status else "연결 거부"))
    report = demo_preflight.Report()
    demo_preflight.check_semgrep_registry(report)
    assert report.rows[0][0] == expected and report.rows[0][1] == "semgrep.dev 접속"
