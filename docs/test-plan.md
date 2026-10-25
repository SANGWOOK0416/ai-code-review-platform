# 테스트 계획 및 결과

**분류 기준** — 범위: 단위 = 함수 하나를 직접 호출 / 통합 = 웹훅 엔드포인트나 분석 파이프라인을 여러 모듈과 함께 실행(외부 API는 mock) / E2E = 실제 GitHub PR + 웹훅 + 실 API.
관점: 블랙 = 입력과 출력(HTTP 응답, 스크립트 산출물)만 확인 / 화이트 = 내부 분기를 알고 함수 단위로 mock·검증 / 그레이 = HTTP로 호출하면서 내부 함수를 mock하거나 호출 여부를 확인.

## 자동 테스트 — 웹훅 (`tests/`, pytest)

실행: `pip install -r requirements-dev.txt && python -m pytest -v` (API 키 불필요 — Anthropic·GitHub·Semgrep 호출은 전부 mock 또는 차단)

| 케이스 ID | 검증 내용 | 범위 | 관점 | 자동/수동 | 결과 |
|---|---|---|---|---|---|
| A1 | HMAC 서명이 틀리거나 본문이 변조되면 401 | 통합 | 블랙 | 자동 | 통과 |
| A2 | 서명 헤더 누락·형식 오류(`sha256=` 아님)면 401 | 통합 | 블랙 | 자동 | 통과 |
| A2b | 서버에 `GITHUB_WEBHOOK_SECRET`이 없으면(None/빈 문자열) 서명 유무·이벤트 종류와 상관없이 500으로 거절(fail-closed)하고 분석을 등록하지 않음. 응답 본문은 원인을 밝히지 않고 로그엔 "시크릿 미설정"만 남음. `/health`는 계속 응답 | 통합 | 그레이 | 자동 | 통과 |
| A3 | 올바른 서명 + `pull_request` `opened`/`synchronize` → 202, `{"status":"accepted", pr_number, action}` | 통합 | 블랙 | 자동 | 통과 |
| A4 | `pull_request`가 아닌 이벤트(ping/push/issues 등)와 처리 대상이 아닌 액션(closed/reopened/edited/labeled)은 200 + `ignored`. 서명 검증이 먼저라 서명 없는 ping은 401 | 통합 | 블랙 | 자동 | 통과 |
| B1 | 서명이 틀리거나 없으면 백그라운드 분석(`process_pr_analysis`)이 등록되지 않음. 대조군: 서명이 맞으면 PR 정보와 함께 정확히 1번 등록 | 통합 | 그레이 | 자동 | 통과 |
| B10 | 202 응답 본문이 먼저 전송되고 그 뒤에 분석 작업이 시작됨 (A3 "즉시 반환" 보강, ASGI 직접 호출) | 통합 | 그레이 | 자동 | 통과 |
| B2 | Semgrep이 해당 카테고리를 탐지하지 않으면 LLM 호출 0회, `low`. 한 카테고리만 탐지되면 그 카테고리에만 LLM 호출 | 통합 | 화이트 | 자동 | 통과 |
| B3 | Semgrep 탐지 + LLM `vulnerable=true` → `high` | 통합 | 화이트 | 자동 | 통과 |
| B4 | Semgrep 탐지 + LLM 안전 + confidence ≥ 임계값 → `filtered` | 통합 | 화이트 | 자동 | 통과 |
| B5 | Semgrep 탐지 + LLM 안전 + confidence < 임계값 → `medium` | 통합 | 화이트 | 자동 | 통과 |
| B6 | 웹훅이 쓰는 임계값이 튜닝값(sqli 0.85 / xss 0.80 / cmdi 0.75 / pathtraver 0.85)과 같은지 | 단위 | 화이트 | 자동 | 통과 |
| B6 | 카테고리별 경계값: 임계값과 같으면 `filtered`, 0.01 낮으면 `medium` (4카테고리 × 2) | 통합 | 화이트 | 자동 | 통과 |
| B7 | `DEMO_CATEGORIES` 미설정이면 CWE-502/798 분석 안 함, `on`이면 Semgrep과 무관하게 LLM으로 판정해 `demo-flagged`/`demo-clear`로 표시. 코멘트 라벨은 짧게(`Hard-coded Credentials (CWE-798)`), LLM 프롬프트 이름은 그대로 | 통합 | 화이트 | 자동 | 통과 |
| B8 | 라인 코멘트·요약 코멘트가 기대한 등급·카테고리·파일·라인으로 게시됨. 4개 카테고리 밖 finding은 "LLM 검증 대상 아님", 라인 코멘트 실패는 요약에 안내 | 통합 | 화이트 | 자동 | 통과 |
| B9 | `semgrep_result_path()`가 Windows 백슬래시·POSIX·혼합 구분자 경로 모두에서 같은 파일명/test_name을 돌려줌 | 단위 | 화이트 | 자동 | 통과 |
| B11 | LLM 호출이 예외를 내면 그 카테고리만 `medium`(Semgrep 단독 판정)으로 처리하고 라인·요약 코멘트를 "LLM 판정 실패로 수동 확인 필요" 사유와 함께 게시. 로그엔 예외 타입만 남고 예외 메시지(가짜 키 문자열)는 로그·코멘트 어디에도 나오지 않음 | 통합 | 화이트 | 자동 | 통과 |
| B12 | 4개 카테고리가 모두 탐지된 파일에서 xss만 LLM이 실패하면 xss만 `medium`, 나머지는 정상 판정(high/filtered/medium)되고 라인 4건 + 요약 1건이 모두 게시됨 | 통합 | 화이트 | 자동 | 통과 |
| B13 | 실제 `classify_file_via_api`에서 응답 잘림(JSON 파싱 `ValidationError`)과 빈 구조화 출력(`parsed_output=None` → `ValueError`)이 나도 `medium`으로 처리됨 (Anthropic 클라이언트만 가짜) | 통합 | 화이트 | 자동 | 통과 |
| B14 | 데모 카테고리에서 LLM이 실패하면 `demo-unavailable`로 표시하고 나머지 데모 판정은 계속함 | 통합 | 화이트 | 자동 | 통과 |
| B15 | LLM을 호출한 카테고리(high/filtered/medium)의 라인 코멘트에 "AI 판단 근거"로 reasoning이 붙고, Semgrep 규칙 메시지는 그 위에 그대로 남음 | 통합 | 화이트 | 자동 | 통과 |
| B16 | 4개 카테고리 밖 finding과 LLM이 실패한 카테고리에는 근거를 붙이지 않고 기존 문구만 남김 | 통합 | 화이트 | 자동 | 통과 |
| B17 | 근거가 600자를 넘으면 잘리고 "이하 생략, 전체 N자" 표시. 여러 줄은 줄마다 인용 표시, 빈 reasoning은 블록 없음 | 단위 | 화이트 | 자동 | 통과 |
| B18 | 근거 속 키·토큰 형태(Anthropic/GitHub/AWS 키, 32자+ hex, `=`·`+`가 있는 base64, `password = "..."`)는 부분 마스킹 — 16자 이상이면 앞 4글자만 남기고 `****`(예: `kPH+****`), 16자 미만은 전부 `****`. 일반 식별자·규칙 ID·CVE 번호와, 실측 reasoning 감사에서 이전 규칙이 잘못 가렸던 문구 5개는 그대로 둠 | 단위 | 화이트 | 자동 | 통과 |
| B19 | 근거 속 `@Override` 같은 문자열이 GitHub 멘션(알림)이 되지 않게 `@` 뒤에 폭 0 공백을 넣음 | 단위 | 화이트 | 자동 | 통과 |
| B20 | 데모 카테고리 판정의 reasoning이 요약 코멘트의 각 데모 항목 아래에 "AI 판단 근거"로 붙고 라인 코멘트와 같은 규칙(600자, 부분 마스킹, 멘션 차단)이 적용됨. LLM 실패(`demo-unavailable`) 항목에는 근거 없음(B14) | 통합 | 화이트 | 자동 | 통과 |
| B21 | LLM 판정마다 서버 로그에 판정 결과와 confidence 값이 남음 | 통합 | 화이트 | 자동 | 통과 |
| B22 | Semgrep 실행 오류 시 PR에 "정적분석 실패로 이번 PR은 분석하지 못함" 요약 코멘트 1개만 게시하고 LLM 호출·라인 코멘트 없음. 오류 원문(프록시 주소, 예외 이름, 종료 코드)은 코멘트에 없고 로그에만 남음 | 통합 | 화이트 | 자동 | 통과 |
| B23 | 시간 초과는 "시간 초과(90초)"로 표시, semgrep 실행 파일 없음(`OSError`)도 같은 실패 코멘트. 웹훅은 Semgrep에 타임아웃 90초를 넘김 | 통합 | 화이트 | 자동 | 통과 |
| B24 | `DEMO_CATEGORIES=on`에서도 Semgrep이 실패하면 데모 카테고리 LLM을 호출하지 않고 실패 코멘트만 게시 | 통합 | 화이트 | 자동 | 통과 |
| B25 | `run_with_timeout` — 제한 시간 안에 끝나면 결과를 그대로 반환, 넘기면 바로 `SemgrepTimeout` (실제 하위 프로세스) | 단위 | 화이트 | 자동 | 통과 |
| B26 | 타임아웃 시 손자 프로세스(semgrep-core에 해당)까지 종료됨 | 단위 | 화이트 | 자동 | 통과 |
| B27 | `run_semgrep`이 타임아웃 값을 넘기고, 종료 코드 2는 `SemgrepError`로 냄 | 단위 | 화이트 | 자동 | 통과 |
| B28 | preflight `semgrep.dev 접속` 항목 — 200이면 OK, 403·연결 실패면 FAIL | 단위 | 화이트 | 자동 | 통과 |

pytest 항목 수: 블랙박스 15 / 화이트·그레이 46 / 단위(B9, B17~B19, B25~B28) 41, 합계 102.

## 자동 테스트 — 기존 CI 회귀 검사 (`.github/workflows/ci.yml`)

커밋된 산출물(`data/processed/`, `data/results/`)을 다시 읽어 스크립트를 실행하고 결과만 확인한다. C1~C5는 pip install 없이 stdlib만으로 돌아간다.

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

E1·E2는 아래 두 수정(LLM 실패 폴백, 시크릿 fail-closed) **이전** 코드로 수행했다.

## 결함 주입 확인 (뮤테이션)

테스트가 실제로 결함을 잡는지 확인하려고, 리포지토리 파일은 그대로 두고 테스트 프로세스 안에서만 `app.main`의 함수·값을 바꿔 전체 스위트(57개)를 돌렸다.

| 주입한 결함 | 실패한 테스트 수 | 잡아낸 케이스 |
|---|---|---|
| 임계값을 4개 카테고리 모두 0.70으로 변경 | 5 | B6 (튜닝값 일치 1 + 경계값 medium 쪽 4) |
| 서명 검증 함수를 아무것도 안 하게 변경 | 14 | A1 ×2, A2 ×2, A4(서명 없는 ping), B1 ×3, A2b ×6 |
| 캐스케이드 게이트 제거(Semgrep 미탐지도 탐지로 취급) | 3 | B2 ×2, B8 |
| LLM 예외를 잡지 않고 그대로 올림 (LLM 실패 폴백 수정 되돌리기) | 4 (+1) | B11, B12, B13 ×2 (+ 데모 경로 B14 — 아래 참고) |
| LLM 실패 시 폴백을 `medium` 대신 `low`로 변경 | 4 | B11, B12, B13 ×2 |
| 시크릿이 없으면 검증을 건너뜀 (fail-closed 수정 되돌리기) | 6 | A2b ×6 |

- 처음 47개 스위트(수정 전)에서 앞의 세 결함은 각각 5 / 8 / 3개가 실패했다. 서명 검증 결함의 실패 수가 14로 늘어난 건 A2b가 이제 `verify_signature`의 거절 동작에 의존하기 때문이다.
- 데모 테스트(B7·B14)는 `DEMO_CATEGORIES=on`을 반영하려고 `app.main`을 다시 import하므로, 그 순간 메모리에 넣은 결함이 사라진다. 그래서 LLM 예외 결함은 reload 직후에 다시 넣는 방식으로 B14만 따로 확인했다(1개 실패, 위 표의 +1).

## 의도된 동작 (변경하지 않음, 2026-10-25 결정)

- 무시되는 이벤트/액션은 202가 아니라 **200** + `ignored`를 반환한다. 202는 "접수 후 백그라운드 처리"에만 쓴다 (A4).
- PR 액션은 `opened`/`synchronize`만 처리하고 `reopened` 등 나머지는 무시한다 (A4).
- 서명 검증이 이벤트 필터보다 먼저 실행되므로, 서명 없는 ping도 무시가 아니라 401을 받는다 — 서명이 확인되지 않은 요청은 이벤트 종류와 상관없이 거절한다 (A4).
- `DEMO_CATEGORIES`는 서버 시작(import) 시점에만 읽고 실행 중에는 바꿀 수 없다. 바꾸려면 서버를 재시작해야 한다 (B7은 모듈 reload로 검증).

## 동작 변경 이력

| 시점 | 변경 | 관련 케이스 |
|---|---|---|
| 테스트 최초 추가 | 현재 동작을 그대로 고정 — 시크릿 미설정 시 서명 검증 생략, LLM 예외 시 PR 전체 분석 중단(코멘트 없음) | A2b, B11 |
| LLM 실패 폴백 | LLM 판정이 실패하면 해당 파일·카테고리만 `medium`(Semgrep 단독 판정)으로 처리하고 분석·코멘트 게시는 계속 — 배치 `merge_hybrid.py`의 "LLM 결과 없음 → medium" 규칙과 같음. 데모 카테고리는 `demo-unavailable` | B11~B14 |
| 시크릿 fail-closed | `GITHUB_WEBHOOK_SECRET`이 없으면 모든 웹훅 요청을 500으로 거절 (운영자가 고쳐야 하는 설정 오류라 503이 아닌 500, `GITHUB_TOKEN` 미설정과 같은 코드) | A2b |
| AI 판단 근거 | LLM 판정을 받은 라인 코멘트와 데모 카테고리 요약에 reasoning을 붙임 (600자 제한, 키 형태 문자열 앞 4글자+`****` 부분 마스킹, `@` 멘션 차단). 가리기 규칙은 저장된 실측 reasoning 1,478건에 돌려 오탐 0건을 확인. 서버 로그에 LLM 판정별 confidence 기록 | B15~B21 |
| Semgrep 실패 처리 | 이전: Semgrep 타임아웃 없음, 실패 시 PR에 코멘트 없이 로그만 남음(응답 없는 차단이면 약 127초 후 실패). 이후: 타임아웃 90초(시간 초과 시 프로세스 트리 종료), 실행 오류·시간 초과 모두 PR에 실패 요약 코멘트 게시(오류 원문은 로그에만). preflight에 semgrep.dev 접속 항목 추가 | B22~B28 |

## 테스트 환경 버전 고정

`requirements-dev.txt`에서 `starlette<1.11`, `httpx<0.29`, `anyio<5`로 상한을 둔다. starlette 1.2부터 TestClient의 httpx 사용에 deprecation 경고가 나오고(현재 CI 환경에서 경고 1건), 이후 버전에서 지원이 빠지면 테스트가 깨지기 때문이다. 상한은 운영 이미지가 쓰는 버전대(1.10)까지 허용한다.
