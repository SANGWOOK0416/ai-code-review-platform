# AI 코드 리뷰 플랫폼 — 캡스톤 프로젝트

> 정적분석 + LLM 하이브리드 기반 설명 가능한 보안 취약점 탐지 시스템

## 1. 프로젝트 정의

**주제**: AI 코드 리뷰 플랫폼 — 정적분석-LLM 하이브리드 기반 설명 가능한 보안 취약점 탐지 시스템

**목표**: 대학원 진학(AI 연구자)과 취업(AI 개발자/백엔드 개발자) 양쪽에 모두 어필 가능한 포트폴리오 겸 졸업 프로젝트

## 2. 주제 선정 배경

- 처음엔 금융(ETF/거시경제 RAG 챗봇)을 검토했으나, 과거에 비슷한 ETF 관련 프로젝트를 수행한 경험이 있어 "성장이 안 보인다"는 리스크를 피하기 위해 도메인·기술을 완전히 다른 축으로 변경
- 최종적으로 AI 코드 리뷰 플랫폼 선택. 이유:
  1. 정적분석 단독/LLM 단독/하이브리드 3방식을 표준 벤치마크(OWASP Benchmark, Juliet Test Suite)로 정량 비교하는 Ablation Study 설계 가능 → 연구방법론 어필
  2. 개발자 도구를 직접 만드는 경험이 AI 개발자·백엔드 개발자 채용에 직접적으로 어필
  3. LLM4SE(LLM for Software Engineering)는 현재 활발히 연구되는 분야 → 대학원 어필
  4. 무료 공개 데이터만으로 실험 가능, 이전 프로젝트와 도메인/기술 모두 겹치지 않음

## 3. 기술 스코프

- **언어**: Java 단일 언어 (OWASP Benchmark가 Java 기반 표준 벤치마크라 평가 신뢰도 확보 목적)
- **대상 CWE 6개 카테고리**:
  1. SQL Injection (CWE-89) — **MVP 1순위**
  2. XSS (CWE-79)
  3. Command Injection (CWE-78)
  4. Path Traversal (CWE-22)
  5. Insecure Deserialization (CWE-502) — ⚠️ **커버리지 갭**: OWASP Benchmark·Juliet Test Suite 모두 데이터 없음 (10장 참고)
  6. Hardcoded Credentials (CWE-798) — ⚠️ **커버리지 갭**: 두 데이터셋 모두 정확히 일치하는 항목 없음 (Juliet에 근접 항목 CWE-259만 존재, 10장 참고)

## 4. 아키텍처 개요

```
GitHub PR 이벤트 → 웹훅 트리거
   → 정적분석(Semgrep/CodeQL)  ─┐
   → LLM 취약점 분석            ─┴→ 하이브리드 결과 통합 → PR 코멘트 게시
```
- 정적분석 결과를 LLM 프롬프트의 grounding 컨텍스트로 제공 → 환각(hallucination) 억제가 핵심 기여점
- 인프라: FastAPI(AI 추론) + Spring Boot(인증/비즈니스 로직) + Docker/CI-CD

## 5. 데이터 소스

| 데이터 | 소스 | 용도 |
|---|---|---|
| 라벨링된 취약점 테스트케이스 | OWASP Benchmark (Java) | Ablation 정량평가 (precision/recall/F1) |
| CWE별 대량 테스트케이스 | Juliet Test Suite (NIST SARD) | 대량 검증, 일반화 성능 |
| 실제 취약점 사례 | CVE/NVD API | 실배포 데모 현실성 |
| 정적분석 베이스라인 | Semgrep, CodeQL (공개 저장소 무료) | 하이브리드 컨텍스트 + 비교 베이스라인 |
| 실제 오픈소스 PR | GitHub API | 실시간 내 데모 |

## 6. 스코프 경계

**포함**: Java만 / CWE 6개 카테고리 / PR diff 단위 리뷰 / 정적분석+LLM 하이브리드
**제외(phase 2)**: 자동 수정(auto-fix), 멀티랭귀지, 실시간 CI 웹훅 연동, 동적분석(DAST)

## 7. 유스케이스 (액터 3개, UC 6개)

- **액터**: 개발자(PR 작성자), GitHub(외부 시스템), 관리자(연구자)
- UC1 PR 리뷰 요청 처리 → UC4(하이브리드 결과 통합) include
- UC4 → UC2(정적분석 실행), UC3(LLM 취약점 분석) include
- UC1 → UC5(리뷰 코멘트 게시) include
- UC6 벤치마크 평가 리포트 조회 (관리자 전용)

*(전체 시나리오 명세는 `캡스톤프로젝트_주제선정보고서.docx` 참고)*

## 8. 진행 로드맵

| 단계 | 내용 |
|---|---|
| 1단계 (MVP) | SQL Injection(CWE-89)만으로 정적분석 단독/LLM 단독/하이브리드 파이프라인 완주, Precision/Recall/F1 비교 |
| 2단계 | 나머지 5개 CWE 카테고리로 확장 |
| 3단계 (진행 중) | GitHub 실제 저장소 연동, Docker/CI-CD로 E2E 배포 — **웹훅 서버 골격은 완성, LLM은 mock 고정 상태로 파이프라인 동작만 증명함** |
| 4단계 | 벤치마크 리포트 정리, 발표 준비 |

## 9. 현재 상태 / 다음 할 일

- [x] 주제 확정
- [x] 데이터 소스·스코프 확정
- [x] 유스케이스 설계 및 지도교수 보고 문서 작성
- [x] 데이터 수집 스크립트 작성 (OWASP Benchmark 4개 카테고리 필터링 완료, Juliet Test Suite는 CWE-502/798 커버리지 확인 목적으로만 조회함 — 본 수집엔 미사용)
- [x] 정적분석(Semgrep) 단독 파이프라인 구현 및 4개 카테고리(sqli/xss/cmdi/pathtraver) 벤치마크 평가 완료
- [x] LLM 단독(Claude Sonnet 5) 파이프라인 스크립트 구현, `--mock` 옵션으로 파이프라인 자체는 검증 완료 (SQLi만)
- [x] 하이브리드(UC4) 통합 로직 설계·구현 (`merge_hybrid.py` + `evaluate_hybrid.py`), SQLi에 한해 mock 데이터로 파이프라인 검증 완료
- [x] CWE-502(Insecure Deserialization), CWE-798(Hardcoded Credentials) 데이터 커버리지 갭 확인 (OWASP Benchmark·Juliet Test Suite 모두 없음 — 10장 참고)
- [x] 3단계 착수: FastAPI 웹훅 서버(`app/main.py`) 구현 — GitHub PR 웹훅 수신 → 변경 `.java` 파일 조회 → Semgrep 스캔 → LLM(mock) 판단 → 하이브리드 통합 → PR에 라인별 리뷰 코멘트 + 요약 코멘트 게시까지 로컬에서 mock 페이로드로 라우팅/파싱 동작 검증 완료 (실제 GitHub PR로는 아직 미검증 — `README_DEPLOY.md` 절차 실행 필요)
- [x] `Dockerfile`(멀티스테이지 빌드) + `requirements.txt` + `.dockerignore` 작성
- [x] `.github/workflows/ci.yml` 작성 — push/PR마다 `evaluate_semgrep.py`(4개 카테고리) + `evaluate_hybrid.py`(sqli) 스모크 테스트 자동 실행
- [ ] **git 저장소 초기화 + 최초 커밋 필요** — 지금까지 로컬 파일로만 존재, CI(`ci.yml`)가 실제로 돌려면 GitHub에 push되어야 하고 `data/processed/`, `data/results/`가 커밋에 포함돼야 함 (`data/raw/`만 gitignore 대상)
- [ ] `README_DEPLOY.md` 절차대로 ngrok + 실제 GitHub 저장소로 엔드투엔드 테스트 (더미 PR 열어서 실제 코멘트가 달리는지 확인) — 아직 미실행
- [ ] **ANTHROPIC_API_KEY 환경변수 설정** 후 `--mock` 없이 실제 데이터로 LLM 단독·하이브리드·웹훅 재실행 필요 (지금까지의 LLM/하이브리드 지표는 전부 mock 데이터 기반이라 무의미함)
- [ ] CWE-502/798 대체 방안 결정 필요 (3단계 실사례 CVE 데이터 활용 또는 별도 데이터셋 조사 — 10장 참고)
- [ ] MVP(SQLi) 파이프라인 전체 완주 (LLM 단독·하이브리드 실제 API 결과로 재계산)

## 10. 리포지토리 메모

- `scripts/download_owasp_benchmark.py`: OWASP Benchmark(Java) 저장소를 clone하고 `expectedresults-1.2.csv`를 파싱해 CWE 카테고리별(기본 SQL Injection/CWE-89)로 필터링 + 해당 소스 파일을 복사하는 스크립트
- `scripts/run_semgrep_scan.py`: `p/java` + `p/owasp-top-ten` 룰셋으로 `data/processed/<category>/sources/`를 스캔해 JSON+SARIF로 저장 (Windows cp949 콘솔에서 SARIF에 포함된 유니코드 문자가 깨지는 걸 막으려 `PYTHONUTF8=1` 강제 설정함). `--category` 인자로 sqli/xss 등 어떤 카테고리든 재사용 가능 (처음부터 일반화되어 있었음)
- `scripts/evaluate_semgrep.py` (구 `evaluate_semgrep_sqli.py`, sqli 전용 → 일반화하며 이름도 변경): semgrep JSON 결과 중 `--category`에 해당하는 CWE 관련 finding만 걸러서 `*_cases.csv` 정답 라벨과 매칭 → Precision/Recall/F1 계산. 카테고리→CWE 번호 매핑(`CATEGORY_TO_CWE`)은 `download_owasp_benchmark.py`와 동일한 값을 사용. p/java, p/owasp-top-ten에는 여러 취약점 룰이 섞여 있어서 반드시 해당 CWE 태그로 필터링해야 공정한 비교가 됨
- `scripts/run_llm_only_sqli.py`: Claude API(`claude-sonnet-5`)만으로 SQLi 여부 판단. **정적분석 결과는 절대 프롬프트에 포함하지 않음**(단독 방식 간 공정 비교를 위해). `output_format`(Pydantic `SqliJudgment`)으로 `{vulnerable, confidence, reasoning}` 구조 강제, 레이트리밋/5xx는 지수 백오프 재시도. `--mock`으로 실제 API 없이 결정론적 가짜 응답을 생성해 파이프라인만 검증 가능. (아직 sqli 전용 — 다른 카테고리로 일반화는 미착수)
- `scripts/evaluate_llm_sqli.py`: `evaluate_semgrep.py`와 동일 패턴으로 LLM 예측 vs 정답 라벨 Precision/Recall/F1 계산. API 실패로 판단이 없는 케이스는 지표 계산에서 제외하고 별도 카운트
- `scripts/merge_hybrid.py` (UC4 통합 로직): `evaluate_semgrep.py`가 만든 `semgrep_predictions.csv`와 `run_llm_only_sqli.py`가 만든 `llm_predictions.json`을 `test_name` 기준으로 매칭. 통합 규칙(OR 룰 + 신뢰도 티어) — 둘 다 탐지 시 `high`, 한쪽만 탐지 시 `medium`(둘 다 `predicted=true`), 둘 다 미탐지 시 `low`(`predicted=false`). `--category`로 재사용 가능하나 현재 LLM 결과가 sqli에만 있어 실질적으로는 sqli만 동작
- `scripts/evaluate_hybrid.py`: `merge_hybrid.py` 산출물로 하이브리드 방식 Precision/Recall/F1 계산 + 신뢰도 티어별(High/Medium/Low) TP/FP/FN/TN 분포까지 리포트 — 세 방식(Semgrep 단독/LLM 단독/하이브리드) 비교의 최종 산출물
- `data/raw/`: 원본 clone 결과 (gitignore 대상, 용량 큼)
- `data/processed/<category>/`: 필터링된 CSV(`<category>_cases.csv`) + 소스 파일 서브셋(`sources/`)
- `data/results/<category>/semgrep/`: semgrep 원본 결과(`semgrep_results.json/.sarif`) + 평가 산출물(`semgrep_predictions.csv`, `semgrep_metrics.json`)
- `data/results/<category>/llm/`: LLM 원본 결과(`llm_predictions.json`) + 평가 산출물(`llm_eval_predictions.csv`, `llm_metrics.json`)
- `data/results/<category>/hybrid/`: 하이브리드 통합 결과(`hybrid_predictions.csv`) + 평가 산출물(`hybrid_metrics.json`)
- `app/main.py` (3단계 웹훅 서버): FastAPI `POST /webhook` — GitHub PR(`opened`/`synchronize`) 이벤트만 처리. `scripts/`의 기존 함수를 **그대로 import해서 재사용**함(로직 이중 구현 방지): `run_semgrep_scan.run_semgrep`(정적분석), `evaluate_semgrep.is_category_finding`+`CATEGORY_TO_CWE`+`CATEGORY_TO_VULN_KEYWORDS`(SQLi 카테고리 판정), `merge_hybrid.confidence_tier`(하이브리드 규칙), `run_llm_only_sqli.classify_file_mock`(LLM은 현재 mock 고정 — 실 API 전환 시 이 한 줄만 `classify_file_via_api`로 교체하면 됨). PR diff에 없는 라인은 GitHub가 라인 코멘트를 거부(422)하므로 실패를 흡수해 요약 코멘트에 안내. `GITHUB_WEBHOOK_SECRET` 설정 시 `X-Hub-Signature-256` HMAC 검증, 미설정 시 경고 로그만 남기고 통과(테스트 편의)
- `merge_hybrid.py`의 `confidence_tier()` 함수: 원래 `merge()` 내부에 있던 신뢰도 티어 판정 로직을 별도 함수로 분리 — `evaluate_hybrid.py`와 `app/main.py` 양쪽에서 동일 규칙을 재사용하기 위함 (분리 전후 SQLi 지표 동일함을 재검증 완료)
- `requirements.txt`: fastapi, uvicorn, requests, pydantic, anthropic, semgrep
- `Dockerfile`: 2단계 빌드(builder에서 `pip install --prefix=/install`, 런타임 스테이지는 그 결과물만 복사) — **musl(alpine) 아닌 `python:3.11-slim`(glibc) 필수**, semgrep이 alpine에서 정상 동작 안 함
- `.dockerignore`: `data/`(전체), `.git/`, `.github/`, `*.md` 등 제외 — 웹훅 서버는 벤치마크 데이터가 필요 없으므로 이미지에서 완전히 배제
- `test-fixtures/VulnerableLogin.java`: 웹훅 데모용 더미 SQLi 취약 파일 — semgrep `tainted-sql-from-http-request` 룰로 실제 탐지되는 것까지 확인함
- `README_DEPLOY.md`: 로컬 서버 실행 → ngrok 터널링 → GitHub 웹훅 등록 → `VulnerableLogin.java`로 실제 PR 열어서 코멘트 확인까지 전체 절차 + 트러블슈팅 표
- `.github/workflows/ci.yml`: push/PR마다 `evaluate_semgrep.py`(sqli/xss/cmdi/pathtraver) + `merge_hybrid.py`+`evaluate_hybrid.py`(sqli)를 실행해 에러 없이 도는지만 확인하는 스모크 테스트. **순수 stdlib라 pip install 불필요** — `data/processed/`, `data/results/`가 커밋되어 있어야 통과함

### Semgrep 단독 방식 벤치마크 결과 (2026-08-03 기준, 4개 카테고리)

| 카테고리 | 전체 케이스 | TP / FP / FN / TN | Precision | Recall | F1-score | Accuracy |
|---|---|---|---|---|---|---|
| SQLi (CWE-89) | 504 | 234 / 143 / 38 / 89 | 0.6207 | 0.8603 | 0.7211 | 0.6409 |
| XSS (CWE-79) | 455 | 202 / 108 / 44 / 101 | 0.6516 | 0.8211 | 0.7266 | 0.6659 |
| Command Injection (CWE-78) | 251 | 112 / 96 / 14 / 29 | 0.5385 | 0.8889 | 0.6707 | 0.5618 |
| Path Traversal (CWE-22) | 268 | 120 / 106 / 13 / 29 | 0.5310 | 0.9023 | 0.6685 | 0.5560 |

Semgrep 단독은 4개 카테고리 모두 **Recall이 Precision보다 뚜렷하게 높은 패턴**(0.82~0.90 vs 0.53~0.65) — 안전한 코드를 오탐(FP)하는 경향이 일관되게 나타남. LLM 단독/하이브리드가 이 오탐을 얼마나 줄이는지가 Ablation의 핵심 관전 포인트.

### 하이브리드(UC4) 파이프라인 검증 결과 — ⚠️ mock 데이터 기반, 참고용 (SQLi만)

| 방식 | TP / FP / FN / TN | Precision | Recall | F1-score |
|---|---|---|---|---|
| Semgrep 단독 | 234 / 143 / 38 / 89 | 0.6207 | 0.8603 | 0.7211 |
| 하이브리드 (Semgrep + **mock** LLM, OR 룰) | 256 / 189 / 16 / 43 | 0.5753 | 0.9412 | 0.7141 |

LLM 쪽이 무작위 mock 응답이라 실제 하이브리드 성능이 아니라 **"OR 룰이 파이프라인 상으로 정상 작동하는지"만 확인된 상태**임. Semgrep 단독 대비 Recall이 오르고 Precision이 떨어지는 방향성 자체는 OR 룰(한쪽만 탐지해도 predicted=true) 설계상 당연한 결과 — API 키 등록 후 실제 LLM 판단으로 재실행해야 의미 있는 비교가 됨.

### CWE 데이터 커버리지 갭 — CWE-502, CWE-798 (2026-08-03 확인)

| CWE | OWASP Benchmark v1.2 | Juliet Test Suite(Java, NIST SARD) |
|---|---|---|
| CWE-502 (Insecure Deserialization) | ❌ 없음 (11개 카테고리 실측 확인: sqli/xss/cmdi/pathtraver/crypto/hash/weakrand/trustbound/securecookie/ldapi/xpathi) | ❌ 없음 (가장 가까운 `CWE499_Sensitive_Data_Serializable`은 다른 취약점) |
| CWE-798 (Use of Hard-coded Credentials) | ❌ 없음 (`trustbound`는 CWE-501이지 CWE-798이 아님 — 혼동 주의) | ⚠️ 정확히 일치하는 항목 없음. 근접 하위 항목 `CWE259_Hard_Coded_Password`만 존재(CWE-798의 좁은 하위 범주) |

두 데이터셋 모두 정량 벤치마크용 라벨링 테스트케이스가 없어서, 프로젝트 스코프 요약 문서에 명시된 6개 CWE 중 이 2개는 **현재 방법론(라벨링된 벤치마크 정량평가)으로 다루기 어려움**. 3단계(실제 오픈소스 PR/CVE 연동) 때 정성적 데모로 다루거나, 다른 CWE로 스코프를 조정하는 방안을 다음 논의에서 결정 필요.

### 다운로드/필터링/스캔 완료 카테고리 (2026-08-03 기준)

| 카테고리 | CWE | 데이터 필터링 | Semgrep 스캔·평가 | LLM 단독 | 하이브리드 |
|---|---|---|---|---|---|
| sqli | 89 | ✅ | ✅ | ⚠️ mock만 | ⚠️ mock만 |
| xss | 79 | ✅ | ✅ | 미착수 | 미착수 |
| cmdi | 78 | ✅ | ✅ | 미착수 | 미착수 |
| pathtraver | 22 | ✅ | ✅ | 미착수 | 미착수 |
| deserial (CWE-502) | 502 | ❌ 데이터 없음 | — | — | — |
| hardcoded credentials (CWE-798) | 798 | ❌ 데이터 없음 | — | — | — |

나머지 확보 가능한 카테고리(crypto/hash/weakrand/trustbound/securecookie/ldapi/xpathi)도 `download_owasp_benchmark.py --category <name>`, `run_semgrep_scan.py --category <name>`, `evaluate_semgrep.py --category <name>`를 그대로 재사용하면 됨.

### 3단계(GitHub 실 연동) 진행상황 (2026-08-03 기준)

**만든 것**: `app/main.py`(FastAPI 웹훅 서버), `Dockerfile`+`requirements.txt`+`.dockerignore`, `test-fixtures/VulnerableLogin.java`(SQLi 데모용 더미 파일), `README_DEPLOY.md`(ngrok+GitHub 웹훅 등록+실PR 테스트 절차), `.github/workflows/ci.yml`.

**로컬에서 검증 완료**:
- `app.main`이 정상 import되고 FastAPI 라우트(`/health`, `/webhook`)가 정상 등록됨
- 서버 기동 후 `GET /health` → `{"status":"ok","llm_mode":"mock"}` 정상 응답
- `POST /webhook`에 가짜 `pull_request`/`opened` 페이로드를 보냈을 때 owner/repo/PR 번호를 정확히 파싱하고 GitHub API(`list_pr_java_files`) 호출까지 정상 진입함 (가짜 토큰이라 401에서 멈추는 것까지 확인 — 즉 라우팅·페이로드 파싱 로직 자체는 검증됨)
- `x-github-event: ping`, `action: closed` 등 처리 대상이 아닌 이벤트/액션은 `{"status":"ignored", ...}`로 정상 무시됨
- `test-fixtures/VulnerableLogin.java`는 semgrep `tainted-sql-from-http-request` 룰로 실제 탐지됨 (README_DEPLOY.md 데모 시나리오가 실제로 작동할 근거)

**아직 검증 안 된 것 (다음 세션에서 확인 필요)**:
- 실제 GitHub 저장소 + ngrok + 진짜 PR로 엔드투엔드 동작 (라인 코멘트/요약 코멘트가 실제로 PR에 달리는지)
- Docker 이미지 빌드 자체 (`docker build` 미실행 — semgrep이 slim 이미지에서 정상 설치·동작하는지 실제 빌드로 확인 필요)
- `.github/workflows/ci.yml`의 실제 GitHub Actions 실행 (git 저장소가 아직 없어서 push 자체가 불가능한 상태)
