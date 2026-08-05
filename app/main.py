"""
FastAPI 웹훅 서버 — GitHub PR 이벤트를 받아 Semgrep 정적분석 + LLM(SQLi) 하이브리드
분석을 실행하고, 결과를 PR에 라인별 리뷰 코멘트 + 요약 코멘트로 게시한다.

3단계(실 연동) MVP 범위:
  - LLM 분석은 ANTHROPIC_API_KEY가 아직 없어 scripts/run_llm_only_sqli.py의
    classify_file_mock()을 그대로 재사용 (실제 API 호출 없음).
    나중에 키가 생기면 이 파일에서 classify_file_mock 호출 한 줄만
    classify_file_via_api(client, source_code)로 바꾸면 됨.
  - 정적분석/하이브리드 통합 로직은 scripts/의 기존 함수를 import해서 그대로 재사용
    (run_semgrep_scan.run_semgrep, evaluate_semgrep.is_category_finding,
    merge_hybrid.confidence_tier) — 로직이 두 군데서 따로 구현되며 어긋나는 걸 방지.

환경변수:
  GITHUB_TOKEN            (필수) PR 파일 조회 + 코멘트 게시용 GitHub 토큰. 코드에 직접 넣지 말 것.
  GITHUB_WEBHOOK_SECRET   (권장) GitHub 웹훅 서명 검증용 secret. 미설정 시 검증을 건너뜀(테스트 전용).
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request

# scripts/의 기존 스크립트를 모듈로 import해서 로직을 재사용한다.
# (각 스크립트는 `if __name__ == "__main__":` 가드가 있어 import 시 CLI가 실행되지 않음)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from run_semgrep_scan import DEFAULT_CONFIGS, run_semgrep  # noqa: E402
from run_llm_only_sqli import classify_file_mock  # noqa: E402
from evaluate_semgrep import CATEGORY_TO_CWE, CATEGORY_TO_VULN_KEYWORDS, is_category_finding  # noqa: E402
from merge_hybrid import confidence_tier  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("webhook")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
GITHUB_API = "https://api.github.com"

SQLI_CWE_TAG = f"CWE-{CATEGORY_TO_CWE['sqli']}"
SQLI_KEYWORDS = CATEGORY_TO_VULN_KEYWORDS["sqli"]

# 캐스케이드 티어를 PR 코멘트에서 사람이 읽을 문구로 옮긴 것.
# 'filtered'라도 코멘트 자체는 계속 게시한다 — 현재 LLM이 mock이라, 검증되지 않은
# 필터로 실제 보안 경보를 조용히 감추는 건 위험하기 때문. 실 API로 전환하고
# 기각 정확도를 확인한 뒤에 억제 여부를 결정할 것.
TIER_VERDICT = {
    "high": "Semgrep 탐지 + LLM도 취약 판단",
    "medium": "Semgrep 탐지, LLM 판단은 불확실 — 확인 권장",
    "filtered": "⚠️ LLM은 오탐으로 판단함 (참고용으로 남김)",
    "low": "Semgrep 미탐지",
}

app = FastAPI(title="AI 코드 리뷰 플랫폼 — 웹훅 서버 (3단계 MVP, LLM=mock)")


# --------------------------------------------------------------------------
# 웹훅 서명 검증
# --------------------------------------------------------------------------
def verify_signature(raw_body: bytes, signature_header: Optional[str]) -> None:
    if not GITHUB_WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET 미설정 — 웹훅 서명 검증을 건너뜁니다 (테스트 전용, 운영 배포 시 필수)")
        return
    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="X-Hub-Signature-256 헤더가 없거나 형식이 잘못됨")
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="웹훅 서명 검증 실패 (secret 불일치 가능성)")


# --------------------------------------------------------------------------
# GitHub API 헬퍼
# --------------------------------------------------------------------------
def gh_headers() -> dict:
    if not GITHUB_TOKEN:
        raise HTTPException(status_code=500, detail="GITHUB_TOKEN 환경변수가 설정되지 않음")
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def list_pr_java_files(owner: str, repo: str, pr_number: int) -> list:
    """PR에서 변경된(삭제 제외) .java 파일 메타데이터 목록을 가져온다."""
    files: list = []
    page = 1
    while True:
        resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files",
            headers=gh_headers(),
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        files.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return [f for f in files if f["filename"].endswith(".java") and f["status"] != "removed"]


def fetch_file_content(owner: str, repo: str, path: str, ref: str) -> str:
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
        headers=gh_headers(),
        params={"ref": ref},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("encoding") != "base64":
        raise ValueError(f"예상치 못한 GitHub contents API 인코딩: {data.get('encoding')}")
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def post_line_comment(owner: str, repo: str, pr_number: int, commit_id: str, path: str, line: int, body: str) -> bool:
    """PR diff 라인에 리뷰 코멘트를 게시. diff 범위 밖 라인이면 GitHub가 422를 반환하므로 실패를 흡수하고 False 반환."""
    resp = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/comments",
        headers=gh_headers(),
        json={"body": body, "commit_id": commit_id, "path": path, "line": line, "side": "RIGHT"},
        timeout=30,
    )
    if resp.status_code >= 300:
        logger.warning("라인 코멘트 게시 실패 (%s:%s) — %s %s", path, line, resp.status_code, resp.text[:300])
        return False
    return True


def post_summary_comment(owner: str, repo: str, pr_number: int, body: str) -> None:
    resp = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/issues/{pr_number}/comments",
        headers=gh_headers(),
        json={"body": body},
        timeout=30,
    )
    resp.raise_for_status()


# --------------------------------------------------------------------------
# 분석 파이프라인 (정적분석 + LLM mock + 하이브리드 통합)
# --------------------------------------------------------------------------
def analyze_pr_files(java_files: list, owner: str, repo: str, head_sha: str) -> dict:
    """PR의 .java 파일들을 받아와 semgrep 스캔 + LLM(mock) SQLi 판단 + 하이브리드 통합을 수행.

    반환값: {"summary_lines": [...], "line_comments": [(real_path, line, body), ...]}
    """
    with tempfile.TemporaryDirectory(prefix="pr_scan_") as tmp_dir:
        sources_dir = Path(tmp_dir) / "sources"
        sources_dir.mkdir()
        output_dir = Path(tmp_dir) / "semgrep_out"

        # GitHub 경로(디렉토리 포함)를 평평한 파일명으로 변환해 임시 디렉토리에 저장
        safe_name_to_path = {}
        for f in java_files:
            content = fetch_file_content(owner, repo, f["filename"], head_sha)
            safe_name = f["filename"].replace("/", "__")
            (sources_dir / safe_name).write_text(content, encoding="utf-8")
            safe_name_to_path[safe_name] = f["filename"]

        # run_semgrep_scan.py 로직 재사용
        semgrep_out = run_semgrep(sources_dir, output_dir, DEFAULT_CONFIGS, ["json"])
        with semgrep_out["json"].open(encoding="utf-8") as fh:
            semgrep_data = json.load(fh)

        findings_by_file: dict = {}
        sqli_flagged_files: set = set()
        for result in semgrep_data.get("results", []):
            safe_name = Path(result["path"]).name
            findings_by_file.setdefault(safe_name, []).append(result)
            if is_category_finding(result, SQLI_CWE_TAG, SQLI_KEYWORDS):
                sqli_flagged_files.add(safe_name)

        summary_lines = [
            "## 🤖 AI 코드 리뷰 (Semgrep + LLM 하이브리드)",
            "",
            f"변경된 `.java` 파일 {len(java_files)}개 분석 완료.",
            "",
        ]
        line_comments: list = []

        for f in java_files:
            safe_name = f["filename"].replace("/", "__")
            real_path = f["filename"]
            source_code = (sources_dir / safe_name).read_text(encoding="utf-8")

            # LLM 분석 — 현재는 API 키가 없어 mock 함수를 그대로 재사용 (실제 판단 아님)
            llm_judgment = classify_file_mock(source_code)
            llm_sqli_detected = bool(llm_judgment.vulnerable)
            semgrep_sqli_detected = safe_name in sqli_flagged_files
            # 캐스케이드 규칙: Semgrep이 탐지한 건만 LLM이 재심사하고, LLM이 충분히
            # 확신할 때(confidence >= reject_threshold)만 경보를 기각한다.
            tier = confidence_tier(
                semgrep_sqli_detected,
                llm_sqli_detected,
                llm_confidence=llm_judgment.confidence,
                llm_available=True,
            )

            file_findings = findings_by_file.get(safe_name, [])
            verdict = TIER_VERDICT.get(tier, tier)
            summary_lines.append(
                f"- `{real_path}`: Semgrep {len(file_findings)}건 탐지 · "
                f"SQLi 하이브리드 판정=**{tier}** ({verdict}) "
                f"(semgrep={semgrep_sqli_detected}, llm[mock]={llm_sqli_detected}, "
                f"llm confidence={llm_judgment.confidence})"
            )

            for finding in file_findings:
                line = finding.get("start", {}).get("line")
                if not line:
                    continue
                rule_id = finding["check_id"]
                message = finding.get("extra", {}).get("message", "")
                is_sqli = is_category_finding(finding, SQLI_CWE_TAG, SQLI_KEYWORDS)
                tier_note = (
                    f" · SQLi 하이브리드 판정: **{tier}** — {verdict}"
                    f" (Semgrep={semgrep_sqli_detected}, LLM[mock]={llm_sqli_detected},"
                    f" confidence={llm_judgment.confidence})"
                    if is_sqli
                    else ""
                )
                body = f"**[{rule_id}]**{tier_note}\n\n{message}"
                line_comments.append((real_path, line, body))

        summary_lines.append("")
        summary_lines.append(
            "_⚠️ LLM 분석은 현재 mock 모드로 실행되었습니다 (ANTHROPIC_API_KEY 미설정) — "
            "실제 취약점 판단이 아니라 파이프라인 동작 검증용입니다._"
        )

        return {"summary_lines": summary_lines, "line_comments": line_comments}


# --------------------------------------------------------------------------
# 엔드포인트
# --------------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_mode": "mock"}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
) -> dict:
    raw_body = await request.body()
    verify_signature(raw_body, x_hub_signature_256)

    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"unsupported event: {x_github_event}"}

    payload: dict = await request.json()
    action = payload.get("action")
    if action not in ("opened", "synchronize"):
        return {"status": "ignored", "reason": f"unsupported action: {action}"}

    pr = payload["pull_request"]
    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]

    logger.info("PR #%s (%s/%s) 분석 시작 — action=%s", pr_number, owner, repo, action)

    java_files = list_pr_java_files(owner, repo, pr_number)
    if not java_files:
        logger.info("PR #%s: 변경된 .java 파일 없음 — 스킵", pr_number)
        return {"status": "skipped", "reason": "변경된 .java 파일 없음"}

    result = analyze_pr_files(java_files, owner, repo, head_sha)

    line_comments_posted = 0
    line_comments_failed = 0
    for real_path, line, body in result["line_comments"]:
        ok = post_line_comment(owner, repo, pr_number, head_sha, real_path, line, body)
        if ok:
            line_comments_posted += 1
        else:
            line_comments_failed += 1

    summary_lines = result["summary_lines"]
    if line_comments_failed:
        summary_lines.append("")
        summary_lines.append(
            f"⚠️ 라인 코멘트 {line_comments_failed}건은 diff 범위 밖 라인이라 게시에 실패했습니다 "
            "(GitHub는 PR diff에 포함되지 않은 라인에 리뷰 코멘트를 허용하지 않음)."
        )

    post_summary_comment(owner, repo, pr_number, "\n".join(summary_lines))

    logger.info(
        "PR #%s 분석 완료 — 파일 %d개, 라인 코멘트 %d건 게시 / %d건 실패",
        pr_number,
        len(java_files),
        line_comments_posted,
        line_comments_failed,
    )
    return {
        "status": "ok",
        "pr_number": pr_number,
        "files_analyzed": len(java_files),
        "line_comments_posted": line_comments_posted,
        "line_comments_failed": line_comments_failed,
    }
