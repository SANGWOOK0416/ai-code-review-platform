"""라이브 데모 스크립트(demo_preflight.py / demo_reset.py) 공용 설정과 GitHub API 호출.

표준 라이브러리만 쓴다. GitHub API는 로그인된 `gh` CLI를 먼저 쓰고, 없거나 실패하면
환경변수 GITHUB_TOKEN으로 직접 호출한다. 토큰 값은 어디에도 출력하지 않는다.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

DEFAULT_REPO = "SANGWOOK0416/ai-code-review-platform"
DEFAULT_SERVER = "http://localhost:8000"
DEFAULT_NGROK_API = "http://127.0.0.1:4040"
BASE_BRANCH = "main"

# 데모 브랜치 = main + 아래 파일들. demo_reset.py는 이 두 브랜치 말고는 절대 건드리지 않는다.
SCENES = {
    "demo/live-scene1": {
        "title": "[데모] 장면 1 — 하이브리드 캐스케이드 (취약/안전/의심 없음)",
        "source_ref": "origin/test/webhook-e2e-real-api",
        "paths": [
            "test-fixtures/e2e/BenchmarkTest00024.java",
            "test-fixtures/e2e/BenchmarkTest00105.java",
            "test-fixtures/e2e/BenchmarkTest00107.java",
        ],
        "demo_categories": "off",
    },
    "demo/live-scene2": {
        "title": "[데모] 장면 2 — CVE-2016-4437 (Apache Shiro 1.2.4) 정성 데모",
        "source_ref": "origin/demo/shiro-cve-2016-4437",
        "paths": [
            "test-fixtures/shiro-cve-demo/AbstractRememberMeManager.java",
            "test-fixtures/shiro-cve-demo/CookieRememberMeManager.java",
            "test-fixtures/shiro-cve-demo/DefaultSerializer.java",
            "test-fixtures/shiro-cve-demo/README.md",
        ],
        "demo_categories": "on",
    },
}


class GitHubAPIError(RuntimeError):
    pass


def github_api(method: str, path: str, body: dict | None = None):
    """GitHub REST API 호출. path는 '/repos/...' 형태. 응답 JSON(dict/list) 또는 None."""
    errors = []
    if shutil.which("gh"):
        cmd = ["gh", "api", "-X", method, path.lstrip("/")]
        if body is not None:
            cmd += ["--input", "-"]
        proc = subprocess.run(
            cmd,
            input=json.dumps(body) if body is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else None
        errors.append(f"gh api 실패(exit {proc.returncode})")

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request = urllib.request.Request(
            "https://api.github.com" + path,
            method=method,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as e:
            errors.append(f"GITHUB_TOKEN 호출 실패(HTTP {e.code})")
        except urllib.error.URLError as e:
            errors.append(f"GITHUB_TOKEN 호출 실패({e.reason})")
    else:
        errors.append("GITHUB_TOKEN 없음")

    raise GitHubAPIError("; ".join(errors))
