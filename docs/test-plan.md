# 테스트 계획 및 결과

**분류 기준** — 범위: 단위 = 함수 하나를 직접 호출 / 통합 = 웹훅 엔드포인트나 분석 파이프라인을 여러 모듈과 함께 실행(외부 API는 mock) / E2E = 실제 GitHub PR + 웹훅 + 실 API.
관점: 블랙 = 입력과 출력(HTTP 응답, 스크립트 산출물)만 확인 / 화이트 = 내부 분기를 알고 함수 단위로 mock·검증 / 그레이 = HTTP로 호출하면서 내부 함수를 mock하거나 호출 여부를 확인.

## 자동 테스트 — 웹훅 (`tests/`, pytest)

실행: `pip install -r requirements-dev.txt && python -m pytest -v` (API 키 불필요 — Anthropic·GitHub·Semgrep 호출은 전부 mock 또는 차단)

| 케이스 ID | 검증 내용 | 범위 | 관점 | 자동/수동 | 결과 |
|---|---|---|---|---|---|
| A1 | HMAC 서명이 틀리거나 본문이 변조되면 401 | 통합 | 블랙 | 자동 | 통과 |
| A2 | secret이 설정된 서버에서 서명 헤더 누락·형식 오류(`sha256=` 아님)면 401 | 통합 | 블랙 | 자동 | 통과 |
| A2b (추가) | secret이 **미설정**이면 서명 검증을 건너뛰어 헤더 없는 요청도 202로 받음 (현재 동작 기록) | 통합 | 그레이 | 자동 | 통과 |
| A3 | 올바른 서명 + `pull_request` `opened`/`synchronize` → 202, `{"status":"accepted", pr_number, action}` | 통합 | 블랙 | 자동 | 통과 |
| A4 | `pull_request`가 아닌 이벤트(ping/push/issues 등)와 처리 대상이 아닌 액션(closed/reopened/edited/labeled)은 **200** + `ignored`. 서명 검증이 먼저라 서명 없는 ping은 401 | 통합 | 블랙 | 자동 | 통과 |
| B1 | 서명이 틀리거나 없으면 백그라운드 분석(`process_pr_analysis`)이 등록되지 않음. 대조군: 서명이 맞으면 PR 정보와 함께 정확히 1번 등록 | 통합 | 그레이 | 자동 | 통과 |
| B10 (추가) | 202 응답 본문이 먼저 전송되고 그 뒤에 분석 작업이 시작됨 (A3 "즉시 반환" 보강, ASGI 직접 호출) | 통합 | 그레이 | 자동 | 통과 |
| B2 | Semgrep이 해당 카테고리를 탐지하지 않으면 LLM 호출 0회, `low`. 한 카테고리만 탐지되면 그 카테고리에만 LLM 호출 | 통합 | 화이트 | 자동 | 통과 |
| B3 | Semgrep 탐지 + LLM `vulnerable=true` → `high` | 통합 | 화이트 | 자동 | 통과 |
| B4 | Semgrep 탐지 + LLM 안전 + confidence ≥ 임계값 → `filtered` | 통합 | 화이트 | 자동 | 통과 |
| B5 | Semgrep 탐지 + LLM 안전 + confidence < 임계값 → `medium` | 통합 | 화이트 | 자동 | 통과 |
| B6 | 웹훅이 쓰는 임계값이 튜닝값(sqli 0.85 / xss 0.80 / cmdi 0.75 / pathtraver 0.85)과 같은지 | 단위 | 화이트 | 자동 | 통과 |
| B6 | 카테고리별 경계값: 임계값과 같으면 `filtered`, 0.01 낮으면 `medium` (4카테고리 × 2) | 통합 | 화이트 | 자동 | 통과 |
| B7 | `DEMO_CATEGORIES` 미설정이면 CWE-502/798 분석 안 함, `on`이면 Semgrep과 무관하게 LLM으로 판정해 `demo-flagged`/`demo-clear`로 표시 | 통합 | 화이트 | 자동 | 통과 |
| B8 | 라인 코멘트·요약 코멘트가 기대한 등급·카테고리·파일·라인으로 게시됨. 4개 카테고리 밖 finding은 "LLM 검증 대상 아님", 라인 코멘트 실패는 요약에 안내 | 통합 | 화이트 | 자동 | 통과 |
| B9 | `semgrep_result_path()`가 Windows 백슬래시·POSIX·혼합 구분자 경로 모두에서 같은 파일명/test_name을 돌려줌 | 단위 | 화이트 | 자동 | 통과 |
| B11 (추가) | LLM 호출이 예외를 내면 카테고리별 폴백 없이 PR 전체 분석이 중단되고 코멘트가 게시되지 않으며, 예외는 PR 번호와 함께 로그에 남음 (현재 동작 기록) | 통합 | 화이트 | 자동 | 통과 |

pytest 항목 수: 블랙박스 15 / 화이트·그레이 26 / 단위(B9) 6, 합계 47.

## 자동 테스트 — 기존 CI 회귀 검사 (`.github/workflows/ci.yml`)

커밋된 산출물(`data/processed/`, `data/results/`)을 다시 읽어 스크립트를 실행하고 결과만 확인한다. 이 스텝들은 pip install 없이 stdlib만으로 돌아간다.

| 케이스 ID | 검증 내용 | 범위 | 관점 | 자동/수동 | 결과 |
|---|---|---|---|---|---|
| C1 | `evaluate_semgrep.py`가 4개 카테고리(sqli/xss/cmdi/pathtraver)에서 에러 없이 실행됨 (스모크) | 통합 | 블랙 | 자동 | 통과 |
| C2 | `merge_hybrid.py`(cascade, or) + `evaluate_hybrid.py`가 sqli에서 에러 없이 실행됨 (스모크) | 통합 | 블랙 | 자동 | 통과 |
| C3 | sqli OR 규칙 결과가 커밋된 기준값과 일치 (회귀) | 통합 | 블랙 | 자동 | 통과 |
| C4 | xss/cmdi/pathtraver cascade 결과가 커밋된 기준값과 일치 (회귀) | 통합 | 블랙 | 자동 | 통과 |
| C5 | `dataset_split.py`/`measure_grounding.py`/`calibrate_confidence.py`/`compare_rules_heldout.py`가 에러 없이 실행됨 (스모크) | 통합 | 블랙 | 자동 | 통과 |
| C6 | 위 웹훅 pytest 스위트(A·B 케이스) 실행 | 단위·통합 | 블랙·화이트·그레이 | 자동 | 통과 |

## 수동 테스트 — 실제 PR E2E

| 케이스 ID | 검증 내용 | 범위 | 관점 | 자동/수동 | 결과 |
|---|---|---|---|---|---|
| E1 | PR #2 — 실제 GitHub PR + ngrok + 실 API 웹훅 E2E | E2E | 블랙 | 수동 | 통과 |
| E2 | PR #3 — Apache Shiro CVE-2016-4437 정성 데모 (`DEMO_CATEGORIES=on`) | E2E | 블랙 | 수동 | 통과 |

## 테스트로 고정한 현재 동작 (수정하지 않음)

- 무시되는 이벤트/액션은 202가 아니라 200을 반환한다 (A4).
- 서명 검증이 이벤트 필터보다 먼저 실행된다 (A4).
- `GITHUB_WEBHOOK_SECRET`이 없으면 서명 검증을 건너뛴다 (A2b).
- 웹훅 경로에서는 LLM 예외가 카테고리별로 처리되지 않아 PR 전체 코멘트가 누락된다 (B11). 배치 스크립트의 "LLM 결과 없음 → medium" 폴백은 웹훅에서는 동작하지 않는다.
- `DEMO_CATEGORIES`는 import 시점에만 읽혀 실행 중에는 바꿀 수 없다 (B7은 모듈 reload로 검증).
