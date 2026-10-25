# 라이브 데모 런북

장면 1: 하이브리드 캐스케이드(취약/안전/의심 없음 3파일) — `demo/live-scene1`, 서버 `DEMO_CATEGORIES` 없음
장면 2: Apache Shiro CVE-2016-4437 정성 데모 — `demo/live-scene2`, 서버 `DEMO_CATEGORIES=on`

두 브랜치는 `main` + 장면 파일 커밋 하나로 준비되어 있어서, 현장에서는 GitHub 비교 화면에서 **Create pull request**만 누르면 된다. 이미 열린 PR #2(장면 1과 같은 파일)·PR #3(장면 2와 같은 파일)은 결과 화면 백업으로 쓴다.

명령은 Git Bash 기준(리허설에서 검증). PowerShell은 `export X=...` 대신 `$env:X="..."`.

## 발표 30분 전 점검

| 시점 | 할 일 | 확인 기준 |
|---|---|---|
| T-30 | 새 터미널에서 `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `GITHUB_WEBHOOK_SECRET`을 설정 (**화면 공유 전에**, 값은 화면에 띄우지 않음) | — |
| T-28 | 데모 브랜치 준비: `python scripts/demo_reset.py` (계획 확인) → `python scripts/demo_reset.py --yes` | 두 장면 모두 "준비 상태", 열린 데모 PR 없음 (약 15초, PR을 닫으면 건당 +7초) |
| T-25 | 서버 기동 (장면 1용, 아래 "서버 기동") | 콘솔 첫 줄 `DEMO_CATEGORIES=off` |
| T-24 | ngrok 기동 (아래 "ngrok 기동") | `Forwarding https://subsidy-sierra-sheath.ngrok-free.dev -> http://localhost:8000` |
| T-22 | `python scripts/demo_preflight.py --scene 1 --server-log "$LOG"` | 8개 항목 전부 OK (약 7초) |
| T-20 | 브라우저 탭 준비: 장면 1·2 비교 화면, PR #2, PR #3, 녹화본 | 아래 "브라우저 탭" |
| T-15 | 녹화본이 바로 재생되는지 확인 | — |
| T-5 | preflight 한 번 더 | 전부 OK |

**서버 기동** (저장소 루트에서, 장면 1은 `DEMO_CATEGORIES`를 설정하지 않는다):
```bash
export LOG="$(cygpath -m "$TEMP")/demo_server.log"   # C:/... 형태라 Windows Python(preflight)도 읽을 수 있음
unset DEMO_CATEGORIES
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 2>&1 | tee "$LOG"
```

**ngrok 기동** (별도 터미널, 예약 도메인이라 재시작해도 URL이 같다 — GitHub 웹훅 설정을 바꿀 필요 없음):
```bash
"$(cygpath -u "$LOCALAPPDATA")/Microsoft/WinGet/Packages/Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe/ngrok.exe" http --url=subsidy-sierra-sheath.ngrok-free.dev 8000
```
`authentication failed ... agent version too old`가 나오면 같은 경로로 `ngrok.exe update` 후 다시 실행.

**브라우저 탭**
- 장면 1 PR 만들기: `https://github.com/SANGWOOK0416/ai-code-review-platform/compare/main...demo/live-scene1?expand=1`
- 장면 2 PR 만들기: `https://github.com/SANGWOOK0416/ai-code-review-platform/compare/main...demo/live-scene2?expand=1`
- 백업 결과 화면: PR #2, PR #3
- 웹훅 전송 기록: 저장소 Settings → Webhooks → (웹훅) → Recent Deliveries

## 현장 조작 — 장면 1

1. 장면 1 비교 탭 → **Create pull request** (제목은 기본값이어도 됨)
2. 서버 콘솔에서 `웹훅 수신` → `202 응답 반환` → `분석 시작` 로그가 바로 뜨는 걸 보여준다
3. 기다리는 동안(약 1분) 캐스케이드 설명: Semgrep이 탐지한 카테고리만 LLM에 묻고, 탐지 없으면 LLM을 부르지 않는다
4. `분석 완료` 로그가 뜨면 PR 화면 새로고침 → 요약 코멘트 1건 + 라인 코멘트 2건
5. 짚을 결과: `BenchmarkTest00024` = **high**, `BenchmarkTest00105` = **filtered**(Semgrep 오탐을 LLM이 기각), `BenchmarkTest00107` = 4개 카테고리 모두 **low**(LLM 호출 없음). LLM 호출은 2번뿐. 00024·00105 라인 코멘트 아래의 **AI 판단 근거**에서 LLM이 왜 그렇게 봤는지(00105는 "조건이 항상 참이라 상수만 들어감") 보여준다
6. 00105가 **medium**으로 나와도 정상이다: SQLi 기각 임계값이 0.85인데 00105의 confidence는 지금까지 0.9 다섯 번, 0.85 한 번이었다. 한 단계만 내려가도(0.8) 기각하지 않고 남기는 쪽으로 판정한다 — "확신이 충분할 때만 Semgrep 경보를 뒤집는다"는 설계로 설명

**리허설 측정값 (2026-10-25, PR #4)**

| 단계 | 소요 |
|---|---|
| Create pull request → 서버 웹훅 수신 | 약 2~6초 (GitHub 전송 지연) |
| 웹훅 수신 → 202 응답 | 0.001초 미만 (GitHub 측 기록 0.51초) |
| 202 → 분석 시작 | 0.003초 |
| PR 파일 목록·내용 조회 | 약 2초 |
| Semgrep 스캔 | 34.5초 (이전 PR #2 때 24.6초 — 매번 차이 있음) |
| LLM 판정 2건 | 11.3초 (6.8초 + 4.5초) |
| 코멘트 게시 | 3.4초 |
| **분석 시작 → 완료** | **51.2초** |
| **PR 생성 요청 → 코멘트 게시 완료** | **약 57초** |

## 현장 조작 — 장면 2

1. 장면 1 서버 콘솔에서 Ctrl+C로 중지 (ngrok은 그대로 둔다)
2. `DEMO_CATEGORIES=on`으로 서버 재시작:
   ```bash
   export DEMO_CATEGORIES=on
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 2>&1 | tee "$LOG"
   ```
   콘솔 첫 줄 `DEMO_CATEGORIES=on` 확인
3. `python scripts/demo_preflight.py --scene 2 --server-log "$LOG"` → 전부 OK
4. 장면 2 비교 탭 → **Create pull request**
5. 기다리는 동안 설명: Semgrep은 이 CVE(하드코딩 키, 역직렬화)를 전혀 탐지하지 못해 캐스케이드로는 LLM이 불리지 않으므로, 데모 카테고리만 캐스케이드 없이 LLM 단독으로 판정한다
6. 결과: 기존 4개 카테고리는 전부 **low**(Semgrep 0건), 정성 데모 구역에서 `AbstractRememberMeManager`가 하드코딩 키 **demo-flagged**, 3개 파일 모두 역직렬화 패턴 **demo-flagged**. 데모 카테고리 LLM 호출 6번(3파일 × 2)

소요 시간: **미측정 (리허설 전)**

## 실패 상황별 대처

판단 기준: **버튼을 누르고 2분이 지나도 코멘트가 없으면 녹화본으로 전환**하고, 원인 확인은 발표 후에 한다.

| 상황 | 알아보는 법 | 대처 |
|---|---|---|
| ngrok 끊김 | ngrok 터미널 종료/재연결 메시지, 서버 콘솔에 `웹훅 수신`이 안 뜸, preflight의 ngrok 항목 FAIL | 같은 명령으로 ngrok 재시작(URL 동일) → Recent Deliveries에서 실패한 전송을 **Redeliver**. 1분 안에 안 되면 녹화본 |
| 웹훅 실패 — 401 | Recent Deliveries 응답 401 | 서버와 GitHub 웹훅의 시크릿이 다름. 현장에서 고치지 말고 녹화본 |
| 웹훅 실패 — 500 `웹훅 서버 설정 오류` | 서버 콘솔에 `웹훅 시크릿 미설정 — 요청 거절` | 서버를 띄운 셸에 `GITHUB_WEBHOOK_SECRET`이 없음 → 설정 후 서버 재시작 → Redeliver |
| 웹훅 전송 자체가 없음 | Recent Deliveries에 새 항목 없음 | 웹훅 비활성 또는 URL 불일치(preflight의 GitHub 웹훅 URL 항목). 녹화본 |
| LLM 지연 | 서버 콘솔이 `Semgrep 스캔` 이후 `LLM 판정 완료` 없이 멈춤 | LLM 호출은 레이트리밋/서버 오류 시 최대 5회 재시도(대기 최대 60초)라 몇 분까지 걸릴 수 있음. 2분 기준으로 녹화본 전환하고, 그동안 PR #2/#3 결과로 설명 |
| LLM 실패 | 콘솔에 `LLM 판정 실패 — ... 예외=...`, 코멘트에 "LLM 판정 실패로 수동 확인 필요" + **medium** (데모 카테고리는 **demo-unavailable**) | 분석과 코멘트 게시는 계속되므로 그대로 보여주고 "LLM 실패 시 Semgrep 단독 판정으로 폴백한다"는 설계로 설명. 나머지 결과는 PR #2/#3으로 보완 |
| 네트워크 차단 (GitHub·Anthropic·ngrok 중 하나라도 막힘) | preflight에서 GitHub 웹훅 URL/ngrok 항목 FAIL, 또는 서버 콘솔에 연결 오류 | 휴대폰 핫스팟으로 바꿔 preflight 재실행. 안 되면 녹화본 + PR #2/#3 화면(오프라인이면 미리 받아둔 스크린샷) |

## 발표 후 정리

```bash
python scripts/demo_reset.py --yes
```
데모로 연 PR을 닫고 두 브랜치를 준비 상태로 되돌린다. `demo/live-scene1`, `demo/live-scene2` 외의 브랜치와 PR(#1~#3 포함), 로컬 작업 트리는 건드리지 않는다. 그다음 서버(Ctrl+C)와 ngrok을 종료한다.

## 화면 공유 시 주의

- 환경변수 값을 출력하는 명령(`echo $GITHUB_TOKEN`, `env`, `set` 등)은 화면 공유 중에 실행하지 않는다. preflight는 값을 출력하지 않는다.
- 서버 콘솔에는 시크릿·API 키 값이 찍히지 않는다(LLM 실패 시에도 예외 타입만 남긴다).
