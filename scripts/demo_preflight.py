"""라이브 데모 직전 점검 — 항목별 OK/FAIL을 출력하고, 하나라도 FAIL이면 exit 1.

사용 예 (Windows PowerShell / Git Bash 공통):
    python scripts/demo_preflight.py --scene 1
    python scripts/demo_preflight.py --scene 2 --server-log demo_server.log

점검 항목:
  1. 서버 /health 응답
  2. 서버 쪽 웹훅 시크릿 설정 — 서명 없는 ping을 보내 401(설정됨)/500(미설정)으로 판별.
     서명 검증에서 바로 거절되므로 분석이 돌거나 코멘트가 달리지 않는다.
  3. ngrok 터널 — 로컬 ngrok API(4040)에서 https 공개 URL과 8000번 포트 연결 확인
  4. GitHub 웹훅 Payload URL이 '<ngrok 공개 URL>/webhook'과 같은지 (GitHub API로 자동 조회)
  4-1. semgrep.dev 접속 (웹훅의 Semgrep이 스캔마다 여기서 룰을 받음)
  5. 이 셸의 GITHUB_WEBHOOK_SECRET / ANTHROPIC_API_KEY / GITHUB_TOKEN 존재 여부 (값은 출력 안 함)
  6. DEMO_CATEGORIES 값 — --scene을 주면 장면에 맞는지(1=off, 2=on) 판정.
     --server-log를 주면 서버 시작 로그의 실제 값으로 판정 (서버는 시작 시점에만 읽음)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_common import (  # noqa: E402
    DEFAULT_NGROK_API,
    DEFAULT_REPO,
    DEFAULT_SERVER,
    SCENES,
    GitHubAPIError,
    github_api,
)

ENV_KEYS = ("GITHUB_WEBHOOK_SECRET", "ANTHROPIC_API_KEY", "GITHUB_TOKEN")


def http(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    """(status, 본문 문자열). 연결 실패면 (None, 오류 설명)."""
    request = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as e:
        return None, str(getattr(e, "reason", e))


class Report:
    def __init__(self):
        self.rows = []

    def add(self, status: str, item: str, detail: str):
        self.rows.append((status, item, detail))
        print(f"[{status:<4}] {item}: {detail}", flush=True)

    @property
    def failed(self) -> bool:
        return any(status == "FAIL" for status, _, _ in self.rows)


def check_health(report: Report, server: str):
    status, text = http("GET", f"{server}/health")
    if status == 200 and '"ok"' in text:
        report.add("OK", "서버 /health", f"200 {text.strip()} (서버 기동 성공 = 시작 시점에 ANTHROPIC_API_KEY 있었음)")
    else:
        report.add("FAIL", "서버 /health", f"응답 없음/비정상 ({status or text}) — uvicorn이 8000번에서 떠 있는지 확인")


def check_server_secret(report: Report, server: str):
    status, _ = http(
        "POST", f"{server}/webhook", body=b"{}",
        headers={"X-GitHub-Event": "ping", "Content-Type": "application/json"},
    )
    if status == 401:
        report.add("OK", "서버 웹훅 시크릿", "설정됨 (서명 없는 요청을 401로 거절)")
    elif status == 500:
        report.add("FAIL", "서버 웹훅 시크릿", "미설정 (500 fail-closed) — GITHUB_WEBHOOK_SECRET 설정 후 서버 재시작")
    else:
        report.add("FAIL", "서버 웹훅 시크릿", f"판별 불가 (응답 {status})")


def check_ngrok(report: Report, ngrok_api: str):
    status, text = http("GET", f"{ngrok_api}/api/tunnels")
    if status != 200:
        report.add("FAIL", "ngrok 터널", f"ngrok 로컬 API 응답 없음 ({status or text}) — ngrok 실행 여부 확인")
        return None
    tunnels = json.loads(text).get("tunnels", [])
    for tunnel in tunnels:
        url = tunnel.get("public_url", "")
        addr = str(tunnel.get("config", {}).get("addr", ""))
        if url.startswith("https://") and addr.endswith(":8000"):
            report.add("OK", "ngrok 터널", f"{url} -> {addr}")
            return url
    report.add("FAIL", "ngrok 터널", f"8000번으로 가는 https 터널 없음 (터널 {len(tunnels)}개)")
    return None


def check_webhook_url(report: Report, repo: str, public_url: str | None):
    if public_url is None:
        report.add("FAIL", "GitHub 웹훅 URL", "ngrok 공개 URL을 몰라 비교 불가")
        return
    expected = public_url.rstrip("/") + "/webhook"
    try:
        hooks = github_api("GET", f"/repos/{repo}/hooks")
    except GitHubAPIError as e:
        report.add(
            "FAIL", "GitHub 웹훅 URL",
            f"자동 조회 실패({e}) — GitHub 저장소 Settings → Webhooks에서 Payload URL이 {expected} 인지 직접 확인",
        )
        return
    pr_hooks = [h for h in hooks if "pull_request" in h.get("events", [])]
    for hook in pr_hooks:
        if hook.get("config", {}).get("url") == expected:
            last = hook.get("last_response", {}) or {}
            state = "활성" if hook.get("active") else "비활성"
            detail = f"{expected} 일치 ({state}, 마지막 응답 {last.get('code')} {last.get('status')})"
            report.add("OK" if hook.get("active") else "FAIL", "GitHub 웹훅 URL", detail)
            return
    registered = ", ".join(h.get("config", {}).get("url", "?") for h in pr_hooks) or "없음"
    report.add("FAIL", "GitHub 웹훅 URL", f"불일치 — 기대 {expected}, 등록된 pull_request 웹훅: {registered}")


SEMGREP_REGISTRY_URL = "https://semgrep.dev/c/p/java"


def check_semgrep_registry(report: Report, url: str = SEMGREP_REGISTRY_URL):
    """웹훅의 Semgrep은 스캔마다 semgrep.dev에서 룰을 받는다 — 막혀 있으면 PR 분석이 통째로 실패한다."""
    status, text = http("GET", url)
    if status == 200:
        report.add("OK", "semgrep.dev 접속", f"200 ({url})")
    else:
        report.add("FAIL", "semgrep.dev 접속", f"룰 다운로드 불가 ({status or text}) — 네트워크/프록시 확인, 안 되면 핫스팟")


def check_env(report: Report):
    for key in ENV_KEYS:
        present = bool(os.environ.get(key))
        report.add("OK" if present else "FAIL", f"환경변수 {key}", "설정됨" if present else "없음")


def server_demo_value(server_log: Path) -> str | None:
    if not server_log.exists():
        return None
    raw = server_log.read_bytes()
    # PowerShell 5.1의 Tee-Object/Out-File은 UTF-16으로 저장한다
    encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    matches = re.findall(r"DEMO_CATEGORIES=(on|off)", raw.decode(encoding, errors="replace"))
    return matches[-1] if matches else None


def check_demo(report: Report, scene: str | None, server_log: Path | None):
    raw = os.environ.get("DEMO_CATEGORIES")
    shell_value = "on" if (raw or "").strip().lower() == "on" else "off"
    shell_text = f"이 셸 값={raw!r} → {shell_value}" if raw is not None else "이 셸 값=미설정 → off"

    server_value = server_demo_value(server_log) if server_log else None
    if server_log and server_value is None:
        report.add("FAIL", "DEMO_CATEGORIES", f"{shell_text}; 서버 로그({server_log})에서 시작 시점 값을 찾지 못함")
        return
    effective = server_value or shell_value
    source = f"서버 시작 로그 값={server_value}" if server_value else "서버 값은 서버 콘솔의 'DEMO_CATEGORIES=' 줄로 확인"
    detail = f"{shell_text}; {source}"

    if scene is None:
        report.add("INFO", "DEMO_CATEGORIES", detail)
        return
    expected = SCENES[f"demo/live-scene{scene}"]["demo_categories"]
    status = "OK" if effective == expected else "FAIL"
    report.add(status, "DEMO_CATEGORIES", f"{detail} (장면 {scene}은 {expected} 필요)")


def main() -> int:
    parser = argparse.ArgumentParser(description="라이브 데모 직전 점검")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--ngrok-api", default=DEFAULT_NGROK_API)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--scene", choices=["1", "2"], help="장면에 맞는 DEMO_CATEGORIES 값인지 판정")
    parser.add_argument("--server-log", type=Path, help="서버 콘솔 출력을 저장한 파일 (DEMO_CATEGORIES 실제 값 확인용)")
    args = parser.parse_args()

    report = Report()
    check_health(report, args.server)
    check_server_secret(report, args.server)
    public_url = check_ngrok(report, args.ngrok_api)
    check_webhook_url(report, args.repo, public_url)
    check_semgrep_registry(report)
    check_env(report)
    check_demo(report, args.scene, args.server_log)

    failed = [item for status, item, _ in report.rows if status == "FAIL"]
    print("\n결과:", "전부 OK" if not failed else f"FAIL {len(failed)}건 — " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
