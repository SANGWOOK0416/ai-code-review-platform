"""웹훅 테스트 공용 설정.

app.main은 import 시점에 환경변수(ANTHROPIC_API_KEY, GITHUB_TOKEN,
GITHUB_WEBHOOK_SECRET, DEMO_CATEGORIES)를 읽으므로 import 전에 가짜 값으로 고정한다.
개발자 셸에 실제 시크릿이 있어도 테스트 프로세스 안에서만 덮어쓴다.
"""
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path

import pytest

TEST_WEBHOOK_SECRET = "test-webhook-secret-not-real"

os.environ["ANTHROPIC_API_KEY"] = "test-anthropic-key-not-real"
os.environ["GITHUB_TOKEN"] = "test-github-token-not-real"
os.environ["GITHUB_WEBHOOK_SECRET"] = TEST_WEBHOOK_SECRET
os.environ.pop("DEMO_CATEGORIES", None)

import app.main as webhook_app  # noqa: E402
import evaluate_semgrep  # noqa: E402
import run_llm_only_sqli  # noqa: E402

DEMO_KEYS = ("deserial", "hardcoded")


class NetworkBlocked(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def block_external_calls(monkeypatch):
    """실제 GitHub/Anthropic/Semgrep 호출을 막는 안전장치 (테스트가 따로 mock하지 않은 경로용)."""

    def _blocked(*args, **kwargs):
        raise NetworkBlocked("테스트 중 외부 호출 차단")

    monkeypatch.setattr("requests.sessions.Session.request", _blocked)
    monkeypatch.setattr("anthropic.resources.messages.Messages.parse", _blocked)
    monkeypatch.setattr("anthropic.resources.messages.Messages.create", _blocked)
    monkeypatch.setattr(webhook_app, "run_semgrep", _blocked)


def sign(body: bytes, secret: str = TEST_WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def pr_payload(action: str = "opened", number: int = 7, sha: str = "deadbeef") -> dict:
    return {
        "action": action,
        "pull_request": {"number": number, "head": {"sha": sha}},
        "repository": {"owner": {"login": "test-owner"}, "name": "test-repo"},
    }


def encode(payload: dict) -> bytes:
    return json.dumps(payload).encode("utf-8")


def finding(cwe: str, line: int = 10, check_id: str = "test.rule") -> dict:
    return {
        "check_id": check_id,
        "start": {"line": line},
        "extra": {"message": f"mock finding {check_id}", "metadata": {"cwe": [f"CWE-{cwe}: mock"]}},
    }


def make_fake_semgrep(findings_by_filename: dict):
    """run_semgrep 대체 — PR 파일명별 finding을 semgrep JSON 형식으로 써서 돌려준다."""

    def fake_run_semgrep(sources_dir, output_dir, configs, formats):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for filename, items in findings_by_filename.items():
            safe_name = filename.replace("/", "__")
            for item in items:
                results.append({"path": str(Path(sources_dir) / safe_name), **item})
        out = output_dir / "semgrep_results.json"
        out.write_text(json.dumps({"results": results}), encoding="utf-8")
        return {"json": out}

    return fake_run_semgrep


class FakeLLM:
    """classify_file_via_api 대체 — 카테고리별 응답을 지정하고 호출 기록을 남긴다.

    responses 값은 (vulnerable, confidence) 튜플이거나, 그 카테고리 호출 시 던질 예외 객체.
    """

    def __init__(self, responses: dict, default=(True, 0.9)):
        self.responses = responses
        self.default = default
        self.calls = []

    def __call__(self, client, source_code, category):
        self.calls.append(category)
        response = self.responses.get(category, self.default)
        if isinstance(response, BaseException):
            raise response
        vulnerable, confidence = response
        return run_llm_only_sqli.VulnJudgment(
            vulnerable=vulnerable, confidence=confidence, reasoning=f"mock reasoning for {category}"
        )


@pytest.fixture
def pipeline(monkeypatch):
    """analyze_pr_files를 외부 호출 없이 돌리기 위한 mock 조립기."""

    def _setup(findings_by_filename: dict, llm_responses: dict = None):
        llm = FakeLLM(llm_responses or {})
        monkeypatch.setattr(webhook_app, "run_semgrep", make_fake_semgrep(findings_by_filename))
        monkeypatch.setattr(webhook_app, "fetch_file_content", lambda owner, repo, path, ref: "class X {}")
        monkeypatch.setattr(webhook_app, "classify_file_via_api", llm)
        return llm

    return _setup


@pytest.fixture
def demo_app(monkeypatch):
    """DEMO_CATEGORIES=on으로 app.main을 다시 import하고, 끝나면 off 상태로 되돌린다."""
    monkeypatch.setenv("DEMO_CATEGORIES", "on")
    importlib.reload(webhook_app)
    yield webhook_app
    for key in DEMO_KEYS:
        evaluate_semgrep.CATEGORY_TO_CWE.pop(key, None)
        run_llm_only_sqli.CATEGORY_TO_NAME.pop(key, None)
    monkeypatch.delenv("DEMO_CATEGORIES", raising=False)
    importlib.reload(webhook_app)


def tier_of(summary_lines: list, category_display_name: str) -> str:
    """요약 코멘트에서 캐스케이드 카테고리 한 줄의 티어(**high** 등)를 뽑는다."""
    prefix = f"  - {category_display_name}:"
    matches = [line for line in summary_lines if line.startswith(prefix)]
    assert len(matches) == 1, f"{category_display_name} 줄이 정확히 1개여야 함: {matches}"
    for tier in ("high", "medium", "filtered", "low"):
        if f"**{tier}**" in matches[0]:
            return tier
    raise AssertionError(f"티어를 찾지 못함: {matches[0]}")
