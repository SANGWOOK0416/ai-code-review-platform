"""블랙박스 테스트 — /webhook에 HTTP 요청을 보내고 응답 코드와 본문만 확인한다.

내부 함수는 mock하지 않는다. conftest의 block_external_calls가 외부 호출(GitHub/Anthropic/
Semgrep)을 막아두지만 이건 안전장치일 뿐이고, 결과 검증에는 쓰지 않는다.
서버 설정은 conftest에서 환경변수로 넣은 가짜 웹훅 secret을 그대로 쓴다.
"""
import pytest
from fastapi.testclient import TestClient

import app.main as webhook_app
from conftest import encode, pr_payload, sign


@pytest.fixture
def client():
    return TestClient(webhook_app.app)


def post(client, body: bytes, event: str = "pull_request", signature=None, include_signature=True):
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    if include_signature:
        headers["X-Hub-Signature-256"] = signature if signature is not None else sign(body)
    return client.post("/webhook", content=body, headers=headers)


class TestSignature:
    def test_invalid_hmac_signature_rejected(self, client):
        """A1: HMAC 서명이 틀리면 401."""
        body = encode(pr_payload("opened"))
        resp = post(client, body, signature=sign(body, secret="wrong-secret"))
        assert resp.status_code == 401

    def test_tampered_body_rejected(self, client):
        """A1: 서명은 원본 본문으로 만들고 본문을 바꿔 보내면 401."""
        original = encode(pr_payload("opened", number=1))
        tampered = encode(pr_payload("opened", number=2))
        resp = post(client, tampered, signature=sign(original))
        assert resp.status_code == 401

    def test_missing_signature_header_rejected(self, client):
        """A2: 서버에 secret이 설정된 상태에서 X-Hub-Signature-256 헤더가 없으면 401."""
        resp = post(client, encode(pr_payload("opened")), include_signature=False)
        assert resp.status_code == 401

    def test_malformed_signature_header_rejected(self, client):
        """A2: 헤더는 있지만 'sha256=' 형식이 아니면 401."""
        resp = post(client, encode(pr_payload("opened")), signature="md5=abc")
        assert resp.status_code == 401


class TestAcceptedEvents:
    @pytest.mark.parametrize("action", ["opened", "synchronize"])
    def test_valid_pr_event_accepted(self, client, action):
        """A3: 올바른 서명 + pull_request opened/synchronize -> 202와 accepted 응답."""
        resp = post(client, encode(pr_payload(action, number=42)))
        assert resp.status_code == 202
        assert resp.json() == {"status": "accepted", "pr_number": 42, "action": action}


class TestIgnoredEvents:
    @pytest.mark.parametrize("event", ["ping", "push", "issues", "pull_request_review"])
    def test_non_pr_event_ignored(self, client, event):
        """A4: pull_request가 아닌 이벤트는 200 + ignored (202가 아님)."""
        body = encode({"zen": "test"})
        resp = post(client, body, event=event)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored", "reason": f"unsupported event: {event}"}

    @pytest.mark.parametrize("action", ["closed", "reopened", "edited", "labeled"])
    def test_non_target_action_ignored(self, client, action):
        """A4: opened/synchronize가 아닌 액션은 200 + ignored (reopened도 처리하지 않음)."""
        resp = post(client, encode(pr_payload(action)))
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored", "reason": f"unsupported action: {action}"}

    def test_unsigned_ping_rejected_before_event_filter(self, client):
        """A4: 서명 검증이 이벤트 필터보다 먼저라, 서명 없는 ping도 무시가 아니라 401."""
        resp = post(client, encode({"zen": "test"}), event="ping", include_signature=False)
        assert resp.status_code == 401
