"""화이트박스 테스트 — app/main.py의 분기 구조를 알고 각 경로를 지나가도록 설계한다.

Semgrep 결과, LLM 응답, GitHub 호출은 conftest의 mock으로 대체한다. 티어는
analyze_pr_files가 반환하는 요약 코멘트 줄에서 읽는다(반환값에 티어 필드가 따로 없음).
"""
import asyncio
import logging
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import app.main as webhook_app
from conftest import encode, finding, pr_payload, sign, tier_of

FILE = "src/Demo.java"
JAVA_FILES = [{"filename": FILE, "status": "added"}]

CATEGORY_CASES = [
    # (카테고리, CWE, 요약 코멘트 표시 이름)
    ("sqli", "89", "SQL Injection"),
    ("xss", "79", "Cross-Site Scripting(XSS)"),
    ("cmdi", "78", "OS Command Injection"),
    ("pathtraver", "22", "Path Traversal"),
]
DISPLAY = {cat: name for cat, _, name in CATEGORY_CASES}


def run_analysis():
    return webhook_app.analyze_pr_files(JAVA_FILES, "test-owner", "test-repo", "deadbeef")


class TestBackgroundScheduling:
    def _post(self, body, signature):
        headers = {"X-GitHub-Event": "pull_request", "Content-Type": "application/json"}
        if signature is not None:
            headers["X-Hub-Signature-256"] = signature
        return TestClient(webhook_app.app).post("/webhook", content=body, headers=headers)

    @pytest.mark.parametrize("signature", ["sha256=" + "0" * 64, None, "md5=abc"])
    def test_rejected_signature_schedules_nothing(self, monkeypatch, signature):
        """B1: 서명이 틀리거나 없으면 401이고, 백그라운드 분석(process_pr_analysis)은 등록되지 않는다."""
        spy = MagicMock()
        monkeypatch.setattr(webhook_app, "process_pr_analysis", spy)
        resp = self._post(encode(pr_payload("opened")), signature)
        assert resp.status_code == 401
        spy.assert_not_called()

    def test_valid_signature_schedules_analysis_once(self, monkeypatch):
        """B1(대조군): 서명이 맞으면 process_pr_analysis가 PR 정보와 함께 정확히 1번 등록된다."""
        spy = MagicMock()
        monkeypatch.setattr(webhook_app, "process_pr_analysis", spy)
        body = encode(pr_payload("synchronize", number=5, sha="abc123"))
        resp = self._post(body, sign(body))
        assert resp.status_code == 202
        spy.assert_called_once_with("test-owner", "test-repo", 5, "abc123", "synchronize")

    def test_response_sent_before_background_work(self, monkeypatch):
        """B10(추가): 202 응답 본문이 먼저 전송되고, 그 다음에 분석 작업이 시작된다 (A3 '즉시 반환' 보강).

        TestClient는 백그라운드 작업이 끝날 때까지 기다린 뒤 응답을 돌려주므로 순서를 볼 수 없다.
        그래서 ASGI 앱을 직접 호출해 send 이벤트와 백그라운드 실행 순서를 기록한다.
        """
        events = []
        monkeypatch.setattr(webhook_app, "process_pr_analysis", lambda *a: events.append("background_started"))
        body = encode(pr_payload("opened"))
        headers = [
            (b"x-github-event", b"pull_request"),
            (b"x-hub-signature-256", sign(body).encode()),
            (b"content-type", b"application/json"),
        ]
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
            "scheme": "http", "path": "/webhook", "raw_path": b"/webhook", "query_string": b"",
            "root_path": "", "headers": headers, "client": ("test", 1), "server": ("test", 80),
        }
        sent = {"body": False}

        async def receive():
            if sent["body"]:
                return {"type": "http.disconnect"}
            sent["body"] = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                events.append(f"status_{message['status']}")
            elif message["type"] == "http.response.body":
                events.append("response_body_sent")

        asyncio.run(webhook_app.app(scope, receive, send))
        assert events == ["status_202", "response_body_sent", "background_started"]


class TestCascade:
    def test_no_semgrep_finding_skips_llm(self, pipeline):
        """B2: Semgrep 탐지가 없으면 4개 카테고리 모두 LLM 호출 0회, 티어 low."""
        llm = pipeline({})
        summary = run_analysis()["summary_lines"]
        assert llm.calls == []
        for _, _, name in CATEGORY_CASES:
            assert tier_of(summary, name) == "low"

    def test_llm_called_only_for_detected_category(self, pipeline):
        """B2: xss만 탐지되면 LLM은 xss에만 1번 호출되고, 탐지 안 된 sqli는 low."""
        llm = pipeline({FILE: [finding("79")]}, {"xss": (True, 0.9)})
        summary = run_analysis()["summary_lines"]
        assert llm.calls == ["xss"]
        assert tier_of(summary, DISPLAY["sqli"]) == "low"
        assert tier_of(summary, DISPLAY["xss"]) == "high"

    def test_detected_and_llm_vulnerable_is_high(self, pipeline):
        """B3: Semgrep 탐지 + LLM vulnerable=True -> high."""
        llm = pipeline({FILE: [finding("89")]}, {"sqli": (True, 0.97)})
        summary = run_analysis()["summary_lines"]
        assert llm.calls == ["sqli"]
        assert tier_of(summary, DISPLAY["sqli"]) == "high"

    def test_detected_and_llm_confident_safe_is_filtered(self, pipeline):
        """B4: Semgrep 탐지 + LLM 안전 + confidence >= 임계값(sqli 0.85) -> filtered."""
        pipeline({FILE: [finding("89")]}, {"sqli": (False, 0.95)})
        assert tier_of(run_analysis()["summary_lines"], DISPLAY["sqli"]) == "filtered"

    def test_detected_and_llm_unsure_safe_is_medium(self, pipeline):
        """B5: Semgrep 탐지 + LLM 안전 + confidence < 임계값(sqli 0.85) -> medium."""
        pipeline({FILE: [finding("89")]}, {"sqli": (False, 0.50)})
        assert tier_of(run_analysis()["summary_lines"], DISPLAY["sqli"]) == "medium"

    def test_thresholds_are_the_tuned_values(self):
        """B6: 웹훅이 쓰는 임계값이 train에서 확정한 카테고리별 값과 같다."""
        assert webhook_app.TUNED_THRESHOLDS == {"sqli": 0.85, "xss": 0.80, "cmdi": 0.75, "pathtraver": 0.85}

    @pytest.mark.parametrize(
        "category, cwe, confidence, expected",
        [
            ("sqli", "89", 0.85, "filtered"), ("sqli", "89", 0.84, "medium"),
            ("xss", "79", 0.80, "filtered"), ("xss", "79", 0.79, "medium"),
            ("cmdi", "78", 0.75, "filtered"), ("cmdi", "78", 0.74, "medium"),
            ("pathtraver", "22", 0.85, "filtered"), ("pathtraver", "22", 0.84, "medium"),
        ],
    )
    def test_threshold_boundary_per_category(self, pipeline, category, cwe, confidence, expected):
        """B6: 카테고리별 경계값 — 임계값과 같으면 filtered, 0.01 낮으면 medium."""
        pipeline({FILE: [finding(cwe)]}, {category: (False, confidence)})
        assert tier_of(run_analysis()["summary_lines"], DISPLAY[category]) == expected


class TestDemoCategories:
    def test_demo_off_by_default(self, pipeline):
        """B7: DEMO_CATEGORIES 미설정이면 CWE-502/798 분석을 하지 않는다."""
        assert webhook_app.DEMO_CATEGORIES_ENABLED is False
        llm = pipeline({})
        summary = run_analysis()["summary_lines"]
        assert "deserial" not in llm.calls and "hardcoded" not in llm.calls
        assert not any("정성 데모" in line for line in summary)

    def test_demo_on_analyzes_502_and_798(self, demo_app, pipeline):
        """B7: DEMO_CATEGORIES=on이면 Semgrep 탐지와 무관하게 deserial/hardcoded를 LLM으로 판정한다."""
        assert demo_app.DEMO_CATEGORIES_ENABLED is True
        llm = pipeline({}, {"deserial": (True, 0.9), "hardcoded": (False, 0.9)})
        summary = demo_app.analyze_pr_files(JAVA_FILES, "o", "r", "s")["summary_lines"]
        assert llm.calls == ["deserial", "hardcoded"]
        text = "\n".join(summary)
        assert "정성 데모 전용" in text
        assert "Insecure Deserialization" in text and "**demo-flagged**" in text
        assert "Use of Hard-coded Credentials" in text and "**demo-clear**" in text


class TestCommentPosting:
    def _wire(self, monkeypatch, pipeline, findings, llm_responses, line_ok=True):
        pipeline({FILE: findings}, llm_responses)
        line_calls, summary_calls = [], []
        monkeypatch.setattr(webhook_app, "list_pr_java_files", lambda o, r, n: JAVA_FILES)
        monkeypatch.setattr(
            webhook_app, "post_line_comment",
            lambda o, r, n, sha, path, line, body: line_calls.append((n, sha, path, line, body)) or line_ok,
        )
        monkeypatch.setattr(
            webhook_app, "post_summary_comment", lambda o, r, n, body: summary_calls.append((n, body))
        )
        return line_calls, summary_calls

    def test_comments_carry_tier_and_category(self, monkeypatch, pipeline):
        """B8: 라인 코멘트와 요약 코멘트가 기대한 등급·카테고리로 게시된다."""
        line_calls, summary_calls = self._wire(
            monkeypatch, pipeline, [finding("89", line=12, check_id="test.sqli.rule")], {"sqli": (True, 0.97)}
        )
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")

        assert len(line_calls) == 1
        pr_number, sha, path, line, body = line_calls[0]
        assert (pr_number, sha, path, line) == (9, "abc", FILE, 12)
        assert "[test.sqli.rule]" in body and "SQL Injection 하이브리드 판정: **high**" in body

        assert len(summary_calls) == 1
        pr_number, summary = summary_calls[0]
        assert pr_number == 9
        assert f"`{FILE}`" in summary
        assert "SQL Injection: 탐지됨" in summary and "**high**" in summary
        assert "Path Traversal: 탐지 없음 → **low**" in summary

    def test_out_of_scope_finding_marked_not_llm_verified(self, monkeypatch, pipeline):
        """B8: 4개 카테고리 밖 finding(CWE-327)은 LLM 검증 없이 'LLM 검증 대상 아님'으로 게시된다."""
        line_calls, _ = self._wire(monkeypatch, pipeline, [finding("327", check_id="test.crypto.rule")], {})
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")
        assert len(line_calls) == 1
        assert "LLM 검증 대상 아님" in line_calls[0][4]

    def test_failed_line_comment_noted_in_summary(self, monkeypatch, pipeline):
        """B8: 라인 코멘트 게시가 실패(diff 범위 밖)하면 요약 코멘트에 실패 건수를 안내한다."""
        _, summary_calls = self._wire(
            monkeypatch, pipeline, [finding("89")], {"sqli": (True, 0.9)}, line_ok=False
        )
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")
        assert "라인 코멘트 1건은 diff 범위 밖" in summary_calls[0][1]

    def test_llm_error_aborts_whole_pr_without_comment(self, monkeypatch, pipeline, caplog):
        """B11(추가, 현재 동작 기록): LLM 호출이 예외를 내면 카테고리별 폴백(medium) 없이
        PR 전체 분석이 중단되고 코멘트가 하나도 게시되지 않는다. 예외는 PR 번호와 함께 로그로 남는다.
        """
        line_calls, summary_calls = self._wire(monkeypatch, pipeline, [finding("89")], {})

        def failing_llm(client, source_code, category):
            raise RuntimeError("simulated LLM failure")

        monkeypatch.setattr(webhook_app, "classify_file_via_api", failing_llm)
        with caplog.at_level(logging.ERROR, logger="webhook"):
            webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")
        assert line_calls == [] and summary_calls == []
        assert any("PR #9" in r.getMessage() for r in caplog.records)


class TestSignatureConfig:
    def test_missing_header_accepted_when_secret_unset(self, monkeypatch):
        """A2-보충(그레이, 현재 동작 기록): 서버에 GITHUB_WEBHOOK_SECRET이 없으면 서명 검증을 건너뛰어
        헤더 없는 요청도 202로 받아들인다.
        """
        monkeypatch.setattr(webhook_app, "GITHUB_WEBHOOK_SECRET", None)
        monkeypatch.setattr(webhook_app, "process_pr_analysis", MagicMock())
        resp = TestClient(webhook_app.app).post(
            "/webhook", content=encode(pr_payload("opened")),
            headers={"X-GitHub-Event": "pull_request", "Content-Type": "application/json"},
        )
        assert resp.status_code == 202
