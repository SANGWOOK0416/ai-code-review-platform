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

    def test_llm_judgment_logged_with_confidence(self, pipeline, caplog):
        """B21: LLM 판정마다 서버 로그에 판정 결과와 confidence 값이 남는다 (코멘트와 같은 값)."""
        pipeline({FILE: [finding("89")]}, {"sqli": (False, 0.85)})
        with caplog.at_level(logging.INFO, logger="webhook"):
            summary = run_analysis()["summary_lines"]
        logs = [r.getMessage() for r in caplog.records if r.getMessage().startswith("LLM 판정 완료")]
        assert len(logs) == 1
        assert f"파일={FILE} 카테고리=sqli vulnerable=False confidence=0.85" in logs[0]
        assert any("confidence=0.85) → **filtered**" in line for line in summary)

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
        assert "    - Insecure Deserialization (CWE-502): LLM 판정=True" in text and "**demo-flagged**" in text
        assert "    - Hard-coded Credentials (CWE-798): LLM 판정=False" in text and "**demo-clear**" in text

    def test_demo_label_short_but_prompt_unchanged(self, demo_app):
        """B7: 코멘트 라벨은 짧게(Hard-coded Credentials (CWE-798)), LLM 프롬프트 이름은 그대로(암호화 키 포함 설명)."""
        import run_llm_only_sqli

        assert demo_app.DEMO_DISPLAY_NAME["hardcoded"] == "Hard-coded Credentials (CWE-798)"
        prompt = run_llm_only_sqli.build_system_prompt("hardcoded")
        assert "암호화 키 하드코딩 포함" in prompt and "CWE-798" in prompt


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

    def test_llm_reasoning_appended_below_semgrep_message(self, monkeypatch, pipeline):
        """B15: LLM을 호출한 카테고리(high/filtered/medium)의 라인 코멘트에 'AI 판단 근거'로 reasoning이 붙고,
        Semgrep 규칙 메시지는 그대로 그 위에 남는다.
        """
        findings = [
            finding("89", line=1, check_id="rule.sqli"),
            finding("79", line=2, check_id="rule.xss"),
            finding("78", line=3, check_id="rule.cmdi"),
        ]
        responses = {
            "sqli": (True, 0.97, "param이 쿼리 문자열에 그대로 연결됨"),
            "xss": (False, 0.95, "출력 전에 HTML 인코딩됨"),
            "cmdi": (False, 0.50, "인자가 고정값일 가능성이 높지만 확실하지 않음"),
        }
        line_calls, _ = self._wire(monkeypatch, pipeline, findings, responses)
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")

        bodies = {call[3]: call[4] for call in line_calls}
        expected = {
            1: ("**high**", "rule.sqli", "SQL Injection", "param이 쿼리 문자열에 그대로 연결됨"),
            2: ("**filtered**", "rule.xss", "Cross-Site Scripting(XSS)", "출력 전에 HTML 인코딩됨"),
            3: ("**medium**", "rule.cmdi", "OS Command Injection", "인자가 고정값일 가능성이 높지만 확실하지 않음"),
        }
        for line, (tier, rule, name, reasoning) in expected.items():
            body = bodies[line]
            assert tier in body
            semgrep_at = body.index(f"mock finding {rule}")
            reasoning_at = body.index(f"**AI 판단 근거** ({name}, LLM):")
            assert semgrep_at < reasoning_at
            assert f"> {reasoning}" in body[reasoning_at:]

    def test_no_reasoning_for_out_of_scope_or_failed_llm(self, monkeypatch, pipeline):
        """B16: 4개 카테고리 밖 finding과 LLM이 실패한 카테고리에는 근거를 붙이지 않고 기존 문구만 남긴다."""
        findings = [finding("327", line=1, check_id="rule.crypto"), finding("89", line=2, check_id="rule.sqli")]
        line_calls, _ = self._wire(monkeypatch, pipeline, findings, {"sqli": RuntimeError("simulated")})
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")
        bodies = {call[3]: call[4] for call in line_calls}
        assert "LLM 검증 대상 아님" in bodies[1] and "AI 판단 근거" not in bodies[1]
        assert "LLM 판정 실패로 수동 확인 필요" in bodies[2] and "AI 판단 근거" not in bodies[2]

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

    def test_llm_error_falls_back_to_medium_and_still_posts(self, monkeypatch, pipeline, caplog):
        """B11: LLM 호출이 예외를 내면 그 카테고리만 medium(Semgrep 단독 판정)으로 처리하고,
        라인·요약 코멘트는 '수동 확인 필요' 사유와 함께 정상 게시된다. 로그엔 예외 타입만 남는다.
        """
        leaked = "sk-ant-THIS-MUST-NOT-APPEAR-IN-LOGS"
        line_calls, summary_calls = self._wire(
            monkeypatch, pipeline, [finding("89", line=12)], {"sqli": RuntimeError(f"boom {leaked}")}
        )
        with caplog.at_level(logging.WARNING, logger="webhook"):
            webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")

        assert len(summary_calls) == 1
        summary = summary_calls[0][1]
        assert "SQL Injection: 탐지됨 → ⚠️ LLM 판정 실패로 수동 확인 필요(RuntimeError) → **medium**" in summary
        assert len(line_calls) == 1
        assert "**medium**" in line_calls[0][4] and "LLM 판정 실패로 수동 확인 필요" in line_calls[0][4]
        assert "AI 판단 근거" not in line_calls[0][4]

        log_text = "\n".join(r.getMessage() for r in caplog.records)
        assert "RuntimeError" in log_text and "sqli" in log_text
        assert leaked not in log_text and leaked not in summary and leaked not in line_calls[0][4]

    def test_one_category_failure_does_not_affect_others(self, monkeypatch, pipeline):
        """B12: 4개 카테고리가 모두 탐지됐는데 xss만 LLM이 실패하면 xss만 medium, 나머지는 정상 판정되고
        코멘트(라인 4건 + 요약 1건)가 모두 게시된다.
        """
        findings = [finding("89", line=1), finding("79", line=2), finding("78", line=3), finding("22", line=4)]
        responses = {
            "sqli": (True, 0.9),
            "xss": TimeoutError("simulated"),
            "cmdi": (False, 0.9),
            "pathtraver": (False, 0.5),
        }
        line_calls, summary_calls = self._wire(monkeypatch, pipeline, findings, responses)
        webhook_app.process_pr_analysis("test-owner", "test-repo", 9, "abc", "opened")

        assert len(line_calls) == 4 and len(summary_calls) == 1
        lines = summary_calls[0][1].split("\n")
        assert tier_of(lines, DISPLAY["sqli"]) == "high"
        assert tier_of(lines, DISPLAY["xss"]) == "medium"
        assert tier_of(lines, DISPLAY["cmdi"]) == "filtered"
        assert tier_of(lines, DISPLAY["pathtraver"]) == "medium"
        failure_lines = [line for line in lines if "LLM 판정 실패" in line]
        assert len(failure_lines) == 1 and failure_lines[0].startswith(f"  - {DISPLAY['xss']}:")


class TestLLMResponseFailures:
    """실제 classify_file_via_api를 쓰되 Anthropic 클라이언트만 가짜로 바꿔, SDK 단계의 실패를 재현한다."""

    class _FakeClient:
        def __init__(self, parse):
            self.messages = type("M", (), {"parse": staticmethod(parse)})()

    def _run(self, monkeypatch, pipeline, parse):
        import run_llm_only_sqli

        pipeline({FILE: [finding("89")]})
        monkeypatch.setattr(webhook_app, "classify_file_via_api", run_llm_only_sqli.classify_file_via_api)
        monkeypatch.setattr(webhook_app, "anthropic_client", self._FakeClient(parse))
        return run_analysis()["summary_lines"]

    def test_truncated_json_falls_back_to_medium(self, monkeypatch, pipeline):
        """B13: 응답이 max_tokens에서 잘려 JSON 파싱(ValidationError)이 실패해도 medium으로 처리된다."""
        import run_llm_only_sqli

        def truncated(**kwargs):
            run_llm_only_sqli.VulnJudgment.model_validate_json('{"vulnerable":true,"confidence":0.9,"reasoning":"잘린')

        summary = self._run(monkeypatch, pipeline, truncated)
        assert tier_of(summary, DISPLAY["sqli"]) == "medium"
        assert any("LLM 판정 실패로 수동 확인 필요(ValidationError)" in line for line in summary)

    def test_missing_parsed_output_falls_back_to_medium(self, monkeypatch, pipeline):
        """B13: 구조화 출력이 비어 있어(parsed_output=None) ValueError가 나도 medium으로 처리된다."""
        summary = self._run(monkeypatch, pipeline, lambda **kwargs: type("R", (), {"parsed_output": None})())
        assert tier_of(summary, DISPLAY["sqli"]) == "medium"
        assert any("LLM 판정 실패로 수동 확인 필요(ValueError)" in line for line in summary)


class TestDemoFailure:
    def test_demo_llm_failure_marked_and_analysis_continues(self, demo_app, pipeline):
        """B14: 데모 카테고리에서 LLM이 실패하면 demo-unavailable로 표시하고 나머지 데모 판정은 계속한다."""
        llm = pipeline({}, {"deserial": RuntimeError("simulated"), "hardcoded": (True, 0.9)})
        summary = demo_app.analyze_pr_files(JAVA_FILES, "o", "r", "s")["summary_lines"]
        text = "\n".join(summary)
        assert llm.calls == ["deserial", "hardcoded"]
        assert "LLM 판정 실패로 수동 확인 필요(RuntimeError) → **demo-unavailable**" in text
        assert "**demo-flagged**" in text
        assert "AI 판단 근거** (Insecure Deserialization" not in text
        assert "AI 판단 근거** (Hard-coded Credentials (CWE-798)" in text

    def test_demo_reasoning_in_summary_with_same_rules(self, demo_app, pipeline):
        """B20: 데모 카테고리 판정의 reasoning이 요약 코멘트의 각 데모 항목 바로 아래에 'AI 판단 근거'로
        붙고, 라인 코멘트와 같은 규칙(600자 자르기, 부분 마스킹, 멘션 차단)이 적용된다.
        """
        long_reasoning = "DEFAULT_CIPHER_KEY_BYTES = Base64.decode(\"kPH+bIxk5D2deZiIxcaaaA==\") @Override " + "근거 " * 400
        pipeline({}, {
            "deserial": (True, 0.92, "ObjectInputStream.readObject()에 타입 검증이 없음"),
            "hardcoded": (True, 0.95, long_reasoning),
        })
        summary = demo_app.analyze_pr_files(JAVA_FILES, "o", "r", "s")["summary_lines"]

        deserial_at = next(i for i, line in enumerate(summary) if line.startswith("    - Insecure Deserialization (CWE-502):"))
        assert summary[deserial_at + 1] == "      **AI 판단 근거** (Insecure Deserialization (CWE-502), LLM):"
        assert summary[deserial_at + 2] == "      > ObjectInputStream.readObject()에 타입 검증이 없음"

        hardcoded_at = next(i for i, line in enumerate(summary) if line.startswith("    - Hard-coded Credentials (CWE-798):"))
        block = summary[hardcoded_at + 2]
        assert block.startswith("      > ")
        assert "kPH+****" in block and "kPH+bIxk5D2deZiIxcaaaA==" not in block
        assert "@\u200bOverride" in block
        assert "… (이하 생략, 전체" in block


class TestSignatureConfig:
    @pytest.mark.parametrize("secret", [None, ""])
    @pytest.mark.parametrize(
        "event, payload, with_header",
        [
            ("pull_request", pr_payload("opened"), False),
            ("pull_request", pr_payload("opened"), True),
            ("ping", {"zen": "test"}, False),
        ],
    )
    def test_requests_rejected_when_secret_unset(self, monkeypatch, caplog, secret, event, payload, with_header):
        """A2b: 서버에 GITHUB_WEBHOOK_SECRET이 없으면(fail-closed) 서명 유무·이벤트 종류와 상관없이 500으로
        거절하고 분석을 등록하지 않는다. 응답 본문은 원인을 밝히지 않고, 로그엔 '시크릿 미설정'만 남는다.
        """
        monkeypatch.setattr(webhook_app, "GITHUB_WEBHOOK_SECRET", secret)
        spy = MagicMock()
        monkeypatch.setattr(webhook_app, "process_pr_analysis", spy)
        body = encode(payload)
        headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
        if with_header:
            headers["X-Hub-Signature-256"] = sign(body)
        with caplog.at_level(logging.ERROR, logger="webhook"):
            resp = TestClient(webhook_app.app).post("/webhook", content=body, headers=headers)

        assert resp.status_code == 500
        assert resp.json() == {"detail": "웹훅 서버 설정 오류"}
        spy.assert_not_called()
        assert [r.getMessage() for r in caplog.records] == ["웹훅 시크릿 미설정 — 요청 거절"]

    def test_health_still_available_when_secret_unset(self, monkeypatch):
        """A2b: 시크릿이 없어도 /health는 응답한다 (거절은 /webhook 요청 단위)."""
        monkeypatch.setattr(webhook_app, "GITHUB_WEBHOOK_SECRET", None)
        assert TestClient(webhook_app.app).get("/health").status_code == 200
