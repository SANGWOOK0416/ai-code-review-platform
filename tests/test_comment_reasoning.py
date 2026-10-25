"""단위 테스트 — 라인 코멘트의 'AI 판단 근거' 블록 (app.main.comment_reasoning_block / redact_secrets)."""
import pytest

from app.main import REASONING_MAX_CHARS, comment_reasoning_block, mask_value, redact_secrets


def test_long_reasoning_truncated_with_marker():
    """B17: 길이 제한을 넘는 reasoning은 잘리고, 잘렸다는 표시와 원래 길이가 붙는다."""
    reasoning = "가나다라 " * 400
    block = comment_reasoning_block(reasoning, "SQL Injection")
    body = block.split("\n", 1)[1]
    assert "… (이하 생략, 전체" in body
    assert len(body) <= REASONING_MAX_CHARS + 40
    short = comment_reasoning_block("짧은 근거", "SQL Injection")
    assert short == "**AI 판단 근거** (SQL Injection, LLM):\n> 짧은 근거"


def test_multiline_reasoning_is_fully_quoted():
    """B17: 여러 줄 reasoning은 줄마다 인용 표시가 붙어 블록이 중간에 끊기지 않는다."""
    block = comment_reasoning_block("첫 줄\r\n\r\n둘째 줄", "XSS")
    assert block.split("\n")[1:] == ["> 첫 줄", ">", "> 둘째 줄"]


@pytest.mark.parametrize("reasoning", [None, "", "   \n "])
def test_empty_reasoning_gives_no_block(reasoning):
    """B17: reasoning이 비어 있으면 블록을 만들지 않는다."""
    assert comment_reasoning_block(reasoning, "SQL Injection") == ""


@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-" + "api03-ABCDEFGHijklmnop1234",  # 이어붙여 저장 — 저장소 시크릿 스캐너 오탐 방지
        "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "github_pat_" + "11ABCDEFG0abcdefghijkl_mnopqrstu",
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "kPH+bIxk5D2deZiIxcaaaA==",  # Shiro 1.2.4 기본 AES 키 (base64)
        "0123456789abcdef0123456789abcdef01234567",  # 40자 hex
    ],
)
def test_secret_like_strings_are_redacted(secret):
    """B18: 키·토큰 형태 문자열은 앞 4글자만 남기고 나머지는 ****로 가린다 (예: kPH+****)."""
    block = comment_reasoning_block(f"코드에 {secret} 값이 하드코딩되어 있음", "Hardcoded")
    assert secret not in block
    assert f"코드에 {secret[:4]}**** 값이" in block


def test_secret_assignment_values_are_redacted():
    """B18: password = "..." / api_key: '...' 처럼 이름 뒤 따옴표 리터럴은 짧아도 가린다 (이름은 남김)."""
    text = redact_secrets("password = \"hunter22\" 이고 api_key: 'abcd1234' 를 사용")
    assert "hunter22" not in text and "abcd1234" not in text
    assert text == "password = \"****\" 이고 api_key: '****' 를 사용"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a" * 15, "****"),            # 16자 미만: 전부 가림
        ("b" * 16, "bbbb****"),        # 16자부터 앞 4글자 유지
        ("hunter22", "****"),
        ("kPH+bIxk5D2deZiIxcaaaA==", "kPH+****"),
    ],
)
def test_mask_length_rule(value, expected):
    """B18: 16자 미만 값은 전부 ****, 16자 이상만 앞 4글자를 남긴다."""
    assert mask_value(value) == expected


def test_short_secret_literal_fully_masked():
    """B18: 이름 뒤 짧은 비밀번호(16자 미만)는 앞글자도 남기지 않는다."""
    assert redact_secrets('token: "abcdefghijklmno"') == 'token: "****"'
    assert redact_secrets('token: "abcdefghijklmnop"') == 'token: "abcd****"'


def test_shiro_default_key_masked_as_documented():
    """B18: 요청 예시 그대로 — Shiro 1.2.4 기본 키는 kPH+****로 표시된다."""
    assert redact_secrets('Base64.decode("kPH+bIxk5D2deZiIxcaaaA==")') == 'Base64.decode("kPH+****")'


@pytest.mark.parametrize(
    "safe_text",
    [
        "getRememberedSerializedIdentity()가 쿠키 값을 반환",
        "BenchmarkTest00024.java의 param",
        "java.lang.security.audit.sqli.tainted-sql-from-http-request",
        "CVE-2016-4437 / CWE-89 / ObjectInputStream.readObject()",
        # 아래는 실측 reasoning 1,478건 감사에서 이전 규칙이 잘못 가렸던 실제 문구
        "--=BenchmarkTest00039 형태의 페이로드",
        "StringBuilder/HashMap/Base64 같은 유틸리티",
        "maliciousName=BenchmarkTest00572",
        "/etc/passwd=BenchmarkTest00529",
        "\"... AND PASSWORD='+bar+'\" 처럼 문자열 연결",
    ],
)
def test_ordinary_code_identifiers_are_kept(safe_text):
    """B18: 일반 코드 식별자·규칙 ID·CVE 번호는 가리지 않는다 (근거를 읽을 수 있어야 함)."""
    assert redact_secrets(safe_text) == safe_text


def test_github_mentions_are_neutralized():
    """B19: '@Override' 같은 문자열이 GitHub 사용자 멘션이 되지 않게 @ 바로 뒤에 폭 0 공백을 넣는다."""
    block = comment_reasoning_block("@Override 메서드와 이메일 a@b.com", "SQL Injection")
    assert "@Override" not in block and "@\u200bOverride" in block
    assert "@\u200bb.com" in block
