"""
FastAPI 웹훅 서버 — GitHub PR 이벤트를 받아 Semgrep 정적분석 + LLM 하이브리드
분석(sqli/xss/cmdi/pathtraver 4개 카테고리)을 실행하고, 결과를 PR에 라인별 리뷰
코멘트 + 요약 코멘트로 게시한다.

3단계(실 연동) MVP 범위:
  - LLM 분석은 scripts/run_llm_only_sqli.py의 classify_file_via_api()를 그대로 재사용
    (Claude Sonnet 5 실 API 호출, VulnJudgment 스키마 강제). ANTHROPIC_API_KEY는
    anthropic.Anthropic()이 환경변수에서 자동으로 읽는다.
  - 정적분석/하이브리드 통합 로직은 scripts/의 기존 함수를 import해서 그대로 재사용
    (run_semgrep_scan.run_semgrep, evaluate_semgrep.is_category_finding,
    merge_hybrid.confidence_tier) — 로직이 두 군데서 따로 구현되며 어긋나는 걸 방지.
  - 캐스케이드 설계상 LLM은 "Semgrep이 그 카테고리를 탐지한 파일"에만 호출한다
    (배치 스크립트의 cascade 결과와 동일하게 만들기 위함 + API 비용 절감).
    Semgrep이 침묵한 카테고리는 LLM 호출 없이 바로 'low' 티어로 처리한다.
  - `/webhook`은 서명 검증 + 이벤트/액션 필터링까지만 동기로 처리하고 즉시 202로
    응답한다. 실제 분석(Semgrep 스캔 + LLM 호출 + PR 코멘트 게시)은 FastAPI
    BackgroundTasks로 넘겨 응답 이후에 처리한다 — Semgrep 스캔(~25초)+LLM 호출이
    GitHub의 웹훅 delivery 타임아웃(~10초)을 넘겨 Recent Deliveries가 500(타임아웃)
    으로 기록되던 문제 대응 (실측 ~41초 vs 타임아웃 ~10초, CLAUDE.md 참고).

환경변수:
  GITHUB_TOKEN            (필수) PR 파일 조회 + 코멘트 게시용 GitHub 토큰. 코드에 직접 넣지 말 것.
  GITHUB_WEBHOOK_SECRET   (권장) GitHub 웹훅 서명 검증용 secret. 미설정 시 검증을 건너뜀(테스트 전용).
  ANTHROPIC_API_KEY       (필수) LLM 판단용 Claude API 키. 코드에 직접 넣지 말 것.
  DEMO_CATEGORIES         (선택) 'on'이면 CWE-502(역직렬화)/CWE-798(하드코딩 자격증명) 정성
                          데모 카테고리를 추가로 분석(기본값 off — 정량 벤치마크 데이터가
                          없는 카테고리이므로 명시적으로 켜야만 동작).
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

import anthropic
import requests
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

# scripts/의 기존 스크립트를 모듈로 import해서 로직을 재사용한다.
# (각 스크립트는 `if __name__ == "__main__":` 가드가 있어 import 시 CLI가 실행되지 않음)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from run_semgrep_scan import DEFAULT_CONFIGS, run_semgrep  # noqa: E402
from run_llm_only_sqli import CATEGORY_TO_NAME, classify_file_via_api  # noqa: E402
from evaluate_semgrep import (  # noqa: E402
    CATEGORY_TO_CWE,
    CATEGORY_TO_VULN_KEYWORDS,
    is_category_finding,
    semgrep_result_path,
)
from merge_hybrid import confidence_tier  # noqa: E402
# reject_threshold 출처: scripts/compare_rules_heldout.py의 TUNED_THRESHOLDS.
# calibrate_confidence.py --sweep으로 train 분할에서 확정한 카테고리별 값(여기서
# 다시 적지 않고 import해서 재사용 — 값이 바뀌면 자동으로 동기화됨, 이중 관리 방지).
from compare_rules_heldout import TUNED_THRESHOLDS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("webhook")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
GITHUB_API = "https://api.github.com"

# anthropic.Anthropic()은 생성 시점에 ANTHROPIC_API_KEY 환경변수를 읽는다 — 키가 없으면
# 서버 기동 시점에 바로 실패하게 해서, 웹훅 요청이 들어온 뒤에야 알게 되는 것을 방지한다.
anthropic_client = anthropic.Anthropic()

SUPPORTED_CATEGORIES = ["sqli", "xss", "cmdi", "pathtraver"]

# 카테고리 -> (CWE 태그, 키워드). evaluate_semgrep.py의 매핑을 그대로 재사용해
# 벤치마크 평가와 웹훅이 같은 기준으로 finding을 분류하게 한다.
CATEGORY_FILTERS = {
    cat: (f"CWE-{CATEGORY_TO_CWE[cat]}", CATEGORY_TO_VULN_KEYWORDS[cat])
    for cat in SUPPORTED_CATEGORIES
}

# 캐스케이드 티어를 PR 코멘트에서 사람이 읽을 문구로 옮긴 것.
# 'filtered'라도 코멘트 자체는 계속 게시한다 — 오프라인 배치 실험(OWASP Benchmark
# 4카테고리, 1,478건)에서는 기각 정확도 1.0000을 확인했지만, 이 웹훅 경로 자체에는
# 아직 운영 데이터가 없으므로 당분간 필터링된 경보도 계속 노출해 모니터링한다.
TIER_VERDICT = {
    "high": "Semgrep 탐지 + LLM도 취약 판단",
    "medium": "Semgrep 탐지, LLM 판단은 불확실 — 확인 권장",
    "filtered": "⚠️ LLM은 오탐으로 판단함 (참고용으로 남김)",
    "low": "Semgrep 미탐지",
}

# --------------------------------------------------------------------------
# 정성 데모 전용 카테고리 (CWE-502 역직렬화 / CWE-798 하드코딩 자격증명)
# --------------------------------------------------------------------------
# OWASP Benchmark에 데이터가 없어 정량 평가가 불가능한 두 카테고리를, 실제 CVE
# (Apache Shiro CVE-2016-4437)로 질적으로만 보여주기 위한 경로. 사전 조사(2026-10)로
# Semgrep 무료 룰셋(p/java+p/owasp-top-ten, 더 넓은 p/security-audit+p/secrets로도)이
# 이 두 CWE 패턴을 전혀 탐지하지 못함을 확인했다 — 기존 캐스케이드(confidence_tier)를
# 그대로 쓰면 Semgrep 미탐지로 LLM이 영원히 호출되지 않는 구조적 문제가 있으므로,
# 캐스케이드와 완전히 분리된 별도 루프에서 LLM을 항상 호출한다(LLM 단독 방식).
# 기본값은 off — 정량 벤치마크가 없는 카테고리를 실수로 운영 PR에 노출하지 않기 위함.
DEMO_CATEGORIES_ENABLED = os.environ.get("DEMO_CATEGORIES", "off").strip().lower() == "on"
DEMO_ONLY_CATEGORIES = ["deserial", "hardcoded"]

if DEMO_CATEGORIES_ENABLED:
    # run_llm_only_sqli.build_system_prompt/build_user_prompt가 참조하는 딕셔너리와
    # 완전히 같은 객체(위 import들이 전부 evaluate_semgrep/run_llm_only_sqli의 모듈
    # 전역을 그대로 가리킴)에 메모리상으로만 항목을 추가한다 — scripts/ 파일은 디스크
    # 에서 전혀 수정하지 않으므로 기존 12개 카테고리·CI 회귀 테스트에는 영향이 없다
    # (이 변경은 이 프로세스가 살아있는 동안에만 유효).
    CATEGORY_TO_CWE["deserial"] = "502"
    CATEGORY_TO_CWE["hardcoded"] = "798"
    CATEGORY_TO_NAME["deserial"] = "Insecure Deserialization"
    # CWE-321(Use of Hard-coded Cryptographic Key)은 MITRE View-1000에서 CWE-798의
    # ChildOf이므로, 프롬프트에 암호화 키도 범위에 포함됨을 명시한다.
    CATEGORY_TO_NAME["hardcoded"] = (
        "Use of Hard-coded Credentials (암호화 키 하드코딩 포함, "
        "CWE-321은 CWE-798의 하위 항목)"
    )

# 캐스케이드 티어(high/medium/filtered/low)와 절대 겹치지 않는 별도 표시 —
# "정성 데모 전용, LLM 단독"임을 티어 이름에서부터 구분하기 위함.
DEMO_VERDICT_FLAGGED = "demo-flagged"
DEMO_VERDICT_CLEAR = "demo-clear"

app = FastAPI(title="AI 코드 리뷰 플랫폼 — 웹훅 서버 (3단계 MVP, LLM=실 API)")


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
# 분석 파이프라인 (정적분석 + LLM 실 API + 하이브리드 통합, 4개 카테고리)
# --------------------------------------------------------------------------
def analyze_pr_files(java_files: list, owner: str, repo: str, head_sha: str) -> dict:
    """PR의 .java 파일들을 받아와 semgrep 스캔 + LLM 판단 + 하이브리드 통합을 수행.

    4개 카테고리(sqli/xss/cmdi/pathtraver) 각각에 대해 캐스케이드 규칙을 적용한다:
    Semgrep이 그 카테고리를 탐지하지 않은 파일은 LLM을 호출하지 않고 바로 'low'
    티어로 처리하고(배치 스크립트의 confidence_tier_cascade와 동일한 단락),
    탐지한 파일만 LLM이 재심사해서 reject_threshold 이상 확신할 때만 'filtered'로
    기각한다. 4개 카테고리 밖의 Semgrep finding은 LLM 검증 없이 그대로 노출한다.

    DEMO_CATEGORIES=on이면 CWE-502/798 정성 데모 카테고리(DEMO_ONLY_CATEGORIES)를
    캐스케이드와 완전히 분리된 별도 루프로 추가 분석한다 — Semgrep 탐지 여부와
    무관하게 항상 LLM을 호출하고, 결과는 summary에만 표시한다(라인 코멘트 없음,
    Semgrep finding 기반이 아니므로 앵커할 라인이 없음).

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

        # finding마다 (있다면) 매칭되는 카테고리를 한 번만 계산해 결과 dict에 붙여둔다
        # — 이후 라인 코멘트 루프에서 재계산하지 않고 그대로 재사용.
        findings_by_file: dict = {}
        flagged_files_by_category: dict = {cat: set() for cat in SUPPORTED_CATEGORIES}
        for result in semgrep_data.get("results", []):
            safe_name = semgrep_result_path(result).name
            matched_cat = None
            for cat, (cwe_tag, keywords) in CATEGORY_FILTERS.items():
                if is_category_finding(result, cwe_tag, keywords):
                    matched_cat = cat
                    flagged_files_by_category[cat].add(safe_name)
                    break
            result["_matched_category"] = matched_cat
            findings_by_file.setdefault(safe_name, []).append(result)

        summary_lines = [
            "## 🤖 AI 코드 리뷰 (Semgrep + LLM 하이브리드, 4개 카테고리)",
            "",
            f"변경된 `.java` 파일 {len(java_files)}개 분석 완료.",
            "",
        ]
        if DEMO_CATEGORIES_ENABLED:
            summary_lines.append(
                "> ⚠️ **DEMO_CATEGORIES=on** — CWE-502/CWE-798 정성 데모 카테고리가 추가로 표시됩니다. "
                "정량 벤치마크 데이터 없음, 캐스케이드 미적용(LLM 단독 판정)."
            )
            summary_lines.append("")
        line_comments: list = []

        for f in java_files:
            safe_name = f["filename"].replace("/", "__")
            real_path = f["filename"]
            source_code = (sources_dir / safe_name).read_text(encoding="utf-8")
            file_findings = findings_by_file.get(safe_name, [])

            # 카테고리별 캐스케이드: Semgrep이 탐지한 카테고리에만 LLM을 호출한다.
            category_results: dict = {}
            for cat in SUPPORTED_CATEGORIES:
                semgrep_detected = safe_name in flagged_files_by_category[cat]
                llm_detected = None
                llm_confidence = None
                if semgrep_detected:
                    # LLM 분석 — Claude Sonnet 5 실 API 호출
                    # (scripts/run_llm_only_sqli.py와 동일 설정)
                    judgment = classify_file_via_api(anthropic_client, source_code, cat)
                    llm_detected = bool(judgment.vulnerable)
                    llm_confidence = judgment.confidence
                tier = confidence_tier(
                    semgrep_detected,
                    bool(llm_detected),
                    llm_confidence=llm_confidence,
                    llm_available=llm_detected is not None,
                    reject_threshold=TUNED_THRESHOLDS[cat],
                )
                category_results[cat] = {
                    "semgrep_detected": semgrep_detected,
                    "llm_detected": llm_detected,
                    "llm_confidence": llm_confidence,
                    "tier": tier,
                }

            summary_lines.append(f"- `{real_path}`: Semgrep {len(file_findings)}건 탐지")
            for cat in SUPPORTED_CATEGORIES:
                r = category_results[cat]
                verdict = TIER_VERDICT.get(r["tier"], r["tier"])
                name = CATEGORY_TO_NAME[cat]
                if not r["semgrep_detected"]:
                    summary_lines.append(f"  - {name}: 탐지 없음 → **{r['tier']}** (LLM 호출 안 함)")
                else:
                    summary_lines.append(
                        f"  - {name}: 탐지됨 → LLM 검증={r['llm_detected']}"
                        f"(confidence={r['llm_confidence']}) → **{r['tier']}** ({verdict})"
                    )

            if DEMO_CATEGORIES_ENABLED:
                summary_lines.append(
                    "  - ⚠️ 정성 데모 전용 (정량 평가 데이터 없음, 캐스케이드 미적용 — LLM 단독):"
                )
                for cat in DEMO_ONLY_CATEGORIES:
                    # 캐스케이드 게이트 없음 — Semgrep 탐지 여부와 무관하게 항상 LLM 호출
                    # (사전 조사로 Semgrep 무료 룰셋이 이 패턴들을 전혀 탐지 못함을 확인했기 때문)
                    judgment = classify_file_via_api(anthropic_client, source_code, cat)
                    demo_verdict = DEMO_VERDICT_FLAGGED if judgment.vulnerable else DEMO_VERDICT_CLEAR
                    name = CATEGORY_TO_NAME[cat]
                    summary_lines.append(
                        f"    - {name}: LLM 판정={judgment.vulnerable}"
                        f"(confidence={judgment.confidence}) → **{demo_verdict}**"
                    )

            for finding in file_findings:
                line = finding.get("start", {}).get("line")
                if not line:
                    continue
                rule_id = finding["check_id"]
                message = finding.get("extra", {}).get("message", "")
                matched_cat = finding.get("_matched_category")
                if matched_cat is None:
                    tier_note = " · LLM 검증 대상 아님 (지원 카테고리 밖 — Semgrep 단독 결과)"
                else:
                    r = category_results[matched_cat]
                    verdict = TIER_VERDICT.get(r["tier"], r["tier"])
                    tier_note = (
                        f" · {CATEGORY_TO_NAME[matched_cat]} 하이브리드 판정: **{r['tier']}** — {verdict}"
                        f" (Semgrep={r['semgrep_detected']}, LLM={r['llm_detected']},"
                        f" confidence={r['llm_confidence']})"
                    )
                body = f"**[{rule_id}]**{tier_note}\n\n{message}"
                line_comments.append((real_path, line, body))

        return {"summary_lines": summary_lines, "line_comments": line_comments}


# --------------------------------------------------------------------------
# 엔드포인트
# --------------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_mode": "real"}


def process_pr_analysis(owner: str, repo: str, pr_number: int, head_sha: str, action: str) -> None:
    """실제 분석(Semgrep 스캔 + LLM 호출 + PR 코멘트 게시) — 응답을 보낸 뒤 백그라운드에서 실행된다.

    여기서 발생하는 예외는 절대 상위로 전파하지 않는다 — BackgroundTasks 안에서
    예외가 나도 서버 프로세스에는 영향이 없지만, 원인을 알 수 있게 PR 번호와
    함께 로그로 남긴다.
    """
    try:
        java_files = list_pr_java_files(owner, repo, pr_number)
        if not java_files:
            logger.info("PR #%s: 변경된 .java 파일 없음 — 스킵", pr_number)
            return

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
    except Exception:
        logger.exception("PR #%s 백그라운드 분석 중 예외 발생 (action=%s)", pr_number, action)


@app.post("/webhook")
async def webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
) -> JSONResponse:
    raw_body = await request.body()
    verify_signature(raw_body, x_hub_signature_256)  # 실패 시 즉시 401 — 백그라운드로 넘기지 않음

    if x_github_event != "pull_request":
        return JSONResponse({"status": "ignored", "reason": f"unsupported event: {x_github_event}"})

    payload: dict = await request.json()
    action = payload.get("action")
    if action not in ("opened", "synchronize"):
        return JSONResponse({"status": "ignored", "reason": f"unsupported action: {action}"})

    pr = payload["pull_request"]
    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]

    logger.info("PR #%s (%s/%s) 웹훅 수신 — action=%s, 백그라운드 분석 큐에 등록", pr_number, owner, repo, action)
    background_tasks.add_task(process_pr_analysis, owner, repo, pr_number, head_sha, action)

    return JSONResponse(
        status_code=202,
        content={"status": "accepted", "pr_number": pr_number, "action": action},
    )
