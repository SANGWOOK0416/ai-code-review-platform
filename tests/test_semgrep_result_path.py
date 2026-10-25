"""단위 테스트 — evaluate_semgrep.semgrep_result_path()의 OS 비의존 경로 파싱.

커밋된 semgrep_results.json은 Windows 절대경로(백슬래시)로 저장되어 있고, Linux CI에서
pathlib.Path로 읽으면 test_name 매칭이 깨졌던 버그(f72ea29에서 수정)의 회귀 방지용.
"""
import pytest

from evaluate_semgrep import semgrep_result_path


@pytest.mark.parametrize(
    "raw_path, expected_name, expected_stem",
    [
        (
            r"C:\Users\82102\Documents\ai-code-review-platform\data\processed\sqli\sources\BenchmarkTest00024.java",
            "BenchmarkTest00024.java",
            "BenchmarkTest00024",
        ),
        (r"sources\BenchmarkTest00105.java", "BenchmarkTest00105.java", "BenchmarkTest00105"),
        ("/tmp/pr_scan_x/sources/src__main__Demo.java", "src__main__Demo.java", "src__main__Demo"),
        ("sources/BenchmarkTest00107.java", "BenchmarkTest00107.java", "BenchmarkTest00107"),
        (r"C:\mixed/dir\sub/File.java", "File.java", "File"),
        ("BenchmarkTest00001.java", "BenchmarkTest00001.java", "BenchmarkTest00001"),
    ],
)
def test_name_and_stem_are_os_independent(raw_path, expected_name, expected_stem):
    """B9: Windows 백슬래시·POSIX·혼합 구분자 경로 모두에서 파일명(name)과 test_name(stem)이 같게 나온다."""
    parsed = semgrep_result_path({"path": raw_path})
    assert parsed.name == expected_name
    assert parsed.stem == expected_stem
