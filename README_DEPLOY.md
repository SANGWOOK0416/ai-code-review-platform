# 로컬에서 실제 GitHub PR로 웹훅 서버 테스트하기

3단계(GitHub 실 연동) MVP 검증용 가이드입니다. LLM 분석은 아직 `ANTHROPIC_API_KEY`가 없어
**mock 모드로 고정**되어 있습니다 — 이 가이드의 목표는 "실제 GitHub PR → 웹훅 → 정적분석 →
(mock)LLM → 하이브리드 통합 → PR 코멘트 게시"라는 **파이프라인 전체가 실제로 동작하는지**
증명하는 것입니다.

## 0. 사전 준비

- Python 3.11 (또는 `requirements.txt`가 설치되는 3.9+)
- GitHub 저장소 하나 (본인 계정의 테스트용 저장소 — public이든 private이든 상관없음)
- [ngrok](https://ngrok.com/download) 계정 (무료 플랜으로 충분)

## 1. 로컬 서버 실행

```bash
pip install -r requirements.txt

# 필수: PR 파일 조회 + 코멘트 게시용 GitHub 토큰
export GITHUB_TOKEN="ghp_..."          # PowerShell: $env:GITHUB_TOKEN="ghp_..."

# 필수: 웹훅 서명 검증용 secret. 아래 4번에서 GitHub 웹훅 설정과 같은 값을 넣어야 함
export GITHUB_WEBHOOK_SECRET="아무-임의-문자열"

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

`GITHUB_WEBHOOK_SECRET`을 설정하지 않으면 서버는 모든 웹훅 요청을 500으로 거절합니다
(fail-closed — ngrok URL이 공개된 동안 누구나 가짜 웹훅을 보낼 수 있으므로 서명 없이는 받지 않음).
`/health`는 secret 없이도 응답합니다.

정상 기동 확인:

```bash
curl http://localhost:8000/health
# {"status":"ok","llm_mode":"mock"}
```

## 2. GitHub Personal Access Token 발급

GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens**로
발급하고, 테스트할 저장소에 대해 다음 권한을 부여하세요:

| 권한 | 레벨 |
|---|---|
| Pull requests | Read and write |
| Contents | Read-only |

발급된 토큰을 위 1번의 `GITHUB_TOKEN`에 넣습니다. **이 토큰을 코드나 커밋에 절대 넣지 마세요.**

## 3. ngrok으로 로컬 서버 터널링

```bash
# 설치 (Windows, choco 사용 시)
choco install ngrok

# 또는 https://ngrok.com/download 에서 직접 다운로드 후 PATH에 추가

# 최초 1회: ngrok 계정의 authtoken 등록 (ngrok 대시보드에서 확인)
ngrok config add-authtoken <YOUR_AUTHTOKEN>

# 로컬 8000번 포트를 외부에 노출
ngrok http 8000
```

실행하면 터미널에 다음과 비슷한 줄이 뜹니다:

```
Forwarding    https://xxxx-xxxx-xxxx.ngrok-free.app -> http://localhost:8000
```

이 `https://xxxx-xxxx-xxxx.ngrok-free.app` 주소가 웹훅 Payload URL의 베이스가 됩니다.
**ngrok 무료 플랜은 재시작할 때마다 URL이 바뀌므로**, 재시작했다면 4번의 웹훅 URL도 다시
업데이트해야 합니다.

## 4. GitHub 저장소에 웹훅 등록

1. 테스트할 저장소 → **Settings → Webhooks → Add webhook**
2. **Payload URL**: `https://xxxx-xxxx-xxxx.ngrok-free.app/webhook` (3번에서 얻은 주소 + `/webhook`)
3. **Content type**: `application/json`
4. **Secret**: 1번에서 설정한 `GITHUB_WEBHOOK_SECRET`과 동일한 값 (비워두면 서버가 서명을 검증할 수 없어 401로 거절됨)
5. **Which events would you like to trigger this webhook?** → "Let me select individual events" 선택 후
   **Pull requests**만 체크 (다른 이벤트는 불필요)
6. Active 체크 후 **Add webhook**

등록 직후 GitHub가 `ping` 이벤트를 한 번 보냅니다. 서버 로그에 요청이 찍히고(웹훅 목록 페이지
하단 "Recent Deliveries"에서 200 응답 확인 가능), `x-github-event: ping`은 우리 서버가
`{"status": "ignored", ...}`으로 무시하는 게 정상입니다 (에러 아님).

## 5. 더미 SQLi 취약 파일로 실제 PR 만들어보기

저장소에 이미 `test-fixtures/VulnerableLogin.java`가 있습니다 — 의도적으로 SQL Injection
(CWE-89)을 심어둔 더미 파일이고, Semgrep의 `tainted-sql-from-http-request` 룰로 실제
탐지되는 것까지 확인된 파일입니다.

```bash
git checkout -b test/webhook-pr-demo
# test-fixtures/VulnerableLogin.java를 살짝 수정 (예: 주석 한 줄 추가)해서 diff를 만들거나,
# 이미 있는 파일 그대로 새 브랜치에서 커밋해도 됨 (신규 브랜치 최초 커밋이면 파일 전체가 diff에 포함됨)
git add test-fixtures/VulnerableLogin.java
git commit -m "test: 웹훅 데모용 SQLi 더미 파일"
git push -u origin test/webhook-pr-demo
```

그 다음 GitHub 웹 UI에서 이 브랜치로 **Pull Request를 오픈**합니다 (`opened` 이벤트 발생).

**기대되는 동작:**

1. GitHub가 `/webhook`으로 `pull_request` / `opened` 이벤트를 전송
2. 서버가 PR에서 변경된 `.java` 파일 목록을 GitHub API로 조회 → `VulnerableLogin.java` 발견
3. 파일 내용을 받아와 임시 디렉토리에 저장 후 Semgrep(`p/java` + `p/owasp-top-ten`) 스캔 실행
4. 같은 파일에 대해 `classify_file_mock()`으로 (가짜) LLM SQLi 판단 실행
5. 하이브리드 통합 규칙 적용 → 신뢰도 티어(`high`/`medium`/`low`) 계산
6. PR에 **라인별 리뷰 코멘트**(Semgrep이 탐지한 각 라인) + **요약 코멘트**(전체 분석 결과, LLM이
   mock임을 명시)가 자동으로 달림

로컬 서버 콘솔에 다음과 비슷한 로그가 남으면 성공입니다:

```
PR #1 (youraccount/your-repo) 분석 시작 — action=opened
PR #1 분석 완료 — 파일 1개, 라인 코멘트 2건 게시 / 0건 실패
```

이후 같은 PR에 커밋을 하나 더 푸시하면(`synchronize` 이벤트) 웹훅이 다시 트리거되어 재분석이
일어나는지도 확인할 수 있습니다.

## 6. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| 웹훅 목록 "Recent Deliveries"에 빨간 X, 401 응답 | `GITHUB_WEBHOOK_SECRET`이 서버와 GitHub 설정에서 서로 다름 |
| 모든 웹훅이 500 `웹훅 서버 설정 오류`, 서버 로그에 `웹훅 시크릿 미설정` | 서버를 실행한 셸에 `GITHUB_WEBHOOK_SECRET`이 없음 — 설정 후 서버 재시작 |
| 500 에러, `GITHUB_TOKEN 환경변수가 설정되지 않음` | 서버를 실행한 셸에 `GITHUB_TOKEN`이 없음 — 새 터미널을 열었다면 다시 `export`/`$env:` 필요 |
| 라인 코멘트 일부가 안 달리고 요약에 "diff 범위 밖" 문구 | GitHub는 PR diff에 실제로 포함된 라인에만 리뷰 코멘트를 허용함 — 정상 동작(요약 코멘트에는 항상 전체 결과가 남음) |
| `semgrep: command not found` (로컬 실행 시) | `pip install -r requirements.txt`가 제대로 안 됐거나 다른 가상환경에서 실행 중 |
| ngrok URL 접속했는데 서버가 안 뜸 | `uvicorn`이 실제로 8000번 포트에서 돌고 있는지, ngrok이 같은 포트를 가리키는지 확인 |
| PR을 열었는데 아무 반응 없음 | 웹훅 이벤트 선택에서 "Pull requests"가 체크됐는지, action이 `opened`/`synchronize`인지 확인 (`closed`, `labeled` 등은 우리 서버가 의도적으로 무시함) |

## 7. Docker로 실행하는 경우

```bash
docker build -t ai-code-review-webhook .
docker run -p 8000:8000 \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e GITHUB_WEBHOOK_SECRET="$GITHUB_WEBHOOK_SECRET" \
  ai-code-review-webhook
```

이후 3~6번 과정은 동일합니다 (ngrok은 여전히 로컬 8000번 포트를 가리킵니다).
