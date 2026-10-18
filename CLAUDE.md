# AI 코드 리뷰 플랫폼 — 캡스톤 프로젝트

> 정적분석 + LLM 하이브리드 기반 설명 가능한 보안 취약점 탐지 시스템

> **다음 세션 시작점 (2026-08-26 기준)**: **연구 파트(1~2단계) + grounding 검증 완료** — 4방식 × 4카테고리 Ablation(held-out) + grounded vs ungrounded 환각률 비교(4카테고리 1,478건 실측, $15.08/$17.94 사용) 완주. 핵심 결론: grounding은 환각률은 낮추지만(4카테고리 전부 0.0000) 교차 파일 헬퍼 오판은 못 고침(0/142 고쳐짐, 8건 오히려 악화) — Semgrep 탐지 여부와 "실제 필요한 정보"(헬퍼 소스)가 다른 종류이기 때문. 다음은 **4단계(최종 리포트 / 발표자료 정리)**. 남은 선택 과제는 CWE-502/798 커버리지 갭 대응과 스키마 필드 순서(reasoning-먼저) 재실험.

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
| 3단계 (진행 중) | GitHub 실제 저장소 연동, Docker/CI-CD로 E2E 배포 — **실제 GitHub 저장소+ngrok+PR로 웹훅 e2e 동작 검증 완료(2026-08-03), LLM은 여전히 mock 고정** |
| 4단계 (**현재 단계**) | 벤치마크 리포트 정리, 발표 준비 — 연구 파트(1~2단계)는 2026-08-25 완료(4방식 × 4카테고리 Ablation, held-out 기준) |

## 9. 현재 상태 / 다음 할 일

- [x] 주제 확정
- [x] 데이터 소스·스코프 확정
- [x] 유스케이스 설계 및 지도교수 보고 문서 작성
- [x] 데이터 수집 스크립트 작성 (OWASP Benchmark 4개 카테고리 필터링 완료, Juliet Test Suite는 CWE-502/798 커버리지 확인 목적으로만 조회함 — 본 수집엔 미사용)
- [x] 정적분석(Semgrep) 단독 파이프라인 구현 및 4개 카테고리(sqli/xss/cmdi/pathtraver) 벤치마크 평가 완료
- [x] LLM 단독(Claude Sonnet 5) 파이프라인을 `--category`로 일반화(`run_llm_only_sqli.py`/`evaluate_llm_sqli.py`)하고 **4개 카테고리(sqli/xss/cmdi/pathtraver) 1,478건 실제 API 실행 완료** (2026-08-25, 실패 0건) — 상세는 10장 "4방식 × 4카테고리 종합 실측 비교" 참고
- [x] 하이브리드(UC4) 통합 로직 설계·구현 (`merge_hybrid.py` + `evaluate_hybrid.py`), **4개 카테고리 전부 실측 LLM 결과로 OR/cascade 양쪽 재평가 완료**
- [x] CWE-502(Insecure Deserialization), CWE-798(Hardcoded Credentials) 데이터 커버리지 갭 확인 (OWASP Benchmark에는 없음(2,740건 재확인), Juliet은 조회 기록만 있고 로컬 원본이 없어 재검증 불가 — 10장 참고)
- [x] 3단계 착수: FastAPI 웹훅 서버(`app/main.py`) 구현 — GitHub PR 웹훅 수신 → 변경 `.java` 파일 조회 → Semgrep 스캔 → LLM(mock) 판단 → 하이브리드 통합 → PR에 라인별 리뷰 코멘트 + 요약 코멘트 게시까지 로컬에서 mock 페이로드로 라우팅/파싱 동작 검증 완료 (이후 ngrok + 실제 GitHub PR로 E2E 검증 완료, 2026-08-03 — 아래 항목 참고)
- [x] `Dockerfile`(멀티스테이지 빌드) + `requirements.txt` + `.dockerignore` 작성
- [x] `.github/workflows/ci.yml` 작성 — push/PR마다 `evaluate_semgrep.py`(4개 카테고리) + `evaluate_hybrid.py`(sqli) 스모크 테스트 자동 실행
- [x] git 저장소 초기화 + 최초 커밋 + GitHub push 완료 (`data/processed/`, `data/results/` 포함, `data/raw/`만 gitignore 대상)
- [x] `README_DEPLOY.md` 절차대로 ngrok + 실제 GitHub 저장소로 엔드투엔드 테스트 완료 (2026-08-03) — 상세는 10장 "3단계 진행상황" 참고
- [x] 하이브리드 통합 규칙 재설계 (2026-08-05) — FP 원인을 실제 케이스로 분석해 **캐스케이드 규칙**(Semgrep 제안 → LLM 검증) 구현, OR 규칙은 비교용으로 유지. `dataset_split.py`(누수 방지 분할) + `measure_grounding.py`(환각률 측정) 신규 작성. 상세는 10장 "통합 규칙 재설계 근거" 참고
- [x] **ANTHROPIC_API_KEY 등록 + SQLi 504건 LLM 단독·하이브리드 실제 API 재실행 완료** (2026-08-25) — MVP(SQLi) 파이프라인 3방식(정적분석 단독/LLM 단독/하이브리드) 전체 완주
- [x] `measure_grounding.py`의 인용 추출 정규식 버그 수정 — "false positive(설명)"류 괄호 서술을 코드 호출로 오인식하던 문제. 실측 데이터 892건 인용을 전수 확인해 STOPWORDS에 반영 (환각률 0.0191→0.0023으로 재측정)
- [x] **나머지 3개 카테고리(xss/cmdi/pathtraver)로 실측 확장 완료** (2026-08-25) — 4개 카테고리 전부에서 LLM 단독 Recall=1.0000, cascade 기각 정확도=1.0000이 재현됨. 상세는 10장 "4방식 × 4카테고리 종합 실측 비교" 참고
- [x] **CI 갭 해소** (2026-08-25) — `ci.yml`에 xss/cmdi/pathtraver 하이브리드 회귀 테스트 추가(cascade 규칙, 커밋된 기준 지표와 일치 검증). 로컬에서 CI 시퀀스 전체(semgrep 4개→sqli 스모크→sqli OR 회귀→xss/cmdi/pathtraver cascade 회귀→분할/grounding 스모크) 재현 후 4개 카테고리 전부 통과 확인 (⚠️ **사후 확인**: 이 "통과 확인"은 Windows 로컬 환경 기준이었고, 실제 Linux GitHub Actions는 이 커밋(`c2d5976`)을 포함해 2026-08-05(`dd1dabb`)부터 2026-10-18 이전까지 계속 failure였음 — 원인과 수정은 아래 "CI의 Linux 실패 원인 조사·수정 완료" 항목 참고)
- [x] **CI의 Linux 실패 원인 조사·수정 완료** (2026-10-18) — GitHub Actions(Linux)가 2026-08-05 커밋(`dd1dabb`, 하이브리드 통합 규칙 재설계)부터 지금까지 계속 failure였음을 발견(그 전 마지막 success는 2026-08-03 `c8c0a65`). **원인**: `evaluate_semgrep.py`(및 `run_llm_grounded.py`, `app/main.py`)가 semgrep JSON의 `path`를 `Path(...).stem`/`.name`으로 파싱하는데, 커밋된 `semgrep_results.json`은 Windows 로컬에서 생성돼 절대경로가 백슬래시로 저장되어 있음 — Linux의 `PosixPath`는 백슬래시를 구분자로 인식하지 못해 전체 경로가 통째로 "파일명"이 되어버려 정답 라벨 CSV와 매칭이 전부 깨짐(모든 case가 predicted=False → TP=0/FP=0, 실측 로그와 정확히 일치). **수정**: `semgrep_result_path()` 공통 헬퍼(백슬래시→슬래시 치환 후 `PurePosixPath`로 강제)를 `evaluate_semgrep.py`에 추가해 3곳(`evaluate_semgrep.py`/`run_llm_grounded.py`/`app/main.py`) 모두 교체. Windows 로컬 재실행으로 4카테고리×3방식(semgrep 단독/cascade/or) TP/FP/FN/TN이 수정 전후 완전히 불변임을 확인한 뒤, `python:3.11-slim` 컨테이너에서 `ci.yml` 전체 시퀀스를 재현해 통과 확인, 커밋(`f72ea29`)·push → **Actions green 확인(2026-10-18, 2026-08-03 이후 첫 성공)**. 웹훅 실 경로(`app/main.py`)는 애초에 같은 프로세스·같은 OS 안에서 스캔 직후 바로 읽어 크로스-OS 경로 불일치가 생기지 않으므로 이 버그의 영향이 없었음(Docker 컨테이너에서 직접 스캔해 CWE-89 정상 탐지 확인, 10장 "3단계 진행상황" 참고).
- [x] **confidence 보정(ECE) 측정 + threshold 튜닝 + held-out 최종 확인 완료** (2026-08-25) — 4개 카테고리 전부 과신(ECE 0.12~0.28), 다만 **threshold 튜닝의 실익은 없음**(기존 기본값 0.7이 이미 F1 최대 구간 안). held-out에서도 기각정확도 1.0000 재현. 상세는 10장 "Confidence 보정 및 threshold 튜닝 결과" 참고
- [x] LLM confidence 백분율 오염 버그 수정 — 모델이 확률(0.92) 대신 백분율(92.0)로 답한 22건(1,478건 중 1.5%)이 검증 없이 저장돼 있었음. `VulnJudgment`에 `field_validator` 추가로 재발 방지 + 기존 데이터 정규화(판정 결과는 불변임을 확인)
- [x] **OR vs cascade held-out 최종 비교 완료** (2026-08-25) — `compare_rules_heldout.py`. cascade가 4개 카테고리 전부에서 OR을 이김(F1 평균 +0.0685). 상세는 10장 "통합 규칙 최종 비교" 참고
- [x] **베이지안 로그오즈 — 착수하지 않기로 결정** (2026-08-25) — (1) threshold 튜닝에서 단순 임계값이 이미 최적점 근처, (2) ECE 0.12~0.28로 보정 없이는 왜곡 위험, (3) 캐스케이드가 held-out에서 이미 견고하게 재현됨. 근거는 10장 "향후 과제" 절에 기록
- [x] **연구 파트(1~2단계) 마무리** — 정적분석 단독/LLM 단독/하이브리드(OR/cascade) 4방식 × 4카테고리 Ablation을 held-out 기준으로 완주
- [x] **`run_llm_grounded.py` 작성 + 4카테고리(1,478건) grounded 실측 완료** (2026-08-26) — 예산 $15.08/$17.94 사용. `measure_grounding.py` 인용 추출기의 2차 버그(부재 주장·페이로드 예시 오인식)를 감사로 발견·수정. grounded 환각률 4카테고리 전부 0.0000(핵심 주장 부합)이나, **교차 파일 헬퍼 오판(예: `BenchmarkTest00052`)은 0/142 고쳐짐, 8건 악화** — 상세는 10장 "교차 파일 헬퍼 오판" 절 참고
- [ ] (선택) 스키마를 `reasoning`이 `vulnerable`보다 먼저 나오도록 재설계해 재실험 — 악화 사례 1건에서 verdict가 reasoning보다 먼저 커밋되는 듯한 패턴 발견(10장 참고). 표본이 1건뿐이라 확증은 아니며, 착수한다면 예산 재확보 필요
- [ ] (선택) grounding 정의를 "Semgrep 탐지 여부"에서 "관련 헬퍼 클래스의 실제 소스"로 확장하는 실험 — 교차 파일 오판을 구조적으로 고칠 수 있는지 검증. 어떤 파일을 "관련"으로 판단할지 자동화 필요, 예산도 재확보 필요
- [ ] CWE-502/798 대체 방안 결정 필요 (3단계 실사례 CVE 데이터 활용 또는 별도 데이터셋 조사 — 10장 참고)
- [x] **웹훅 mock→실 API 전환**: 코드·로컬·Docker 검증 완료, **실제 PR E2E 검증 완료(2026-10-18, PR #2)** — `BenchmarkTest00024`(취약)→**high**, `BenchmarkTest00105`(안전)→**filtered**, `BenchmarkTest00107`(Semgrep 미탐지)→**low**(LLM 호출 0건) 전부 배치 결과와 정확히 일치, 라인 코멘트 2건·요약 코멘트 정상 게시, 실 API 호출 2건 사용. 단 **처리 시간(~41초)이 GitHub 웹훅 delivery 타임아웃(~10초)을 초과해 GitHub Recent Deliveries에는 500(타임아웃)으로 기록됨** — 기능 자체는 정상(응답 소켓이 끊긴 뒤에도 서버가 분석을 끝까지 진행해 코멘트는 별도 REST 호출로 정상 게시됨)이지만, 운영 전환 전에는 즉시 200 ACK 후 백그라운드로 분석하는 비동기 구조로 개선이 필요함. 10장 참고

## 10. 리포지토리 메모

- `scripts/download_owasp_benchmark.py`: OWASP Benchmark(Java) 저장소를 clone하고 `expectedresults-1.2.csv`를 파싱해 CWE 카테고리별(기본 SQL Injection/CWE-89)로 필터링 + 해당 소스 파일을 복사하는 스크립트
- `scripts/run_semgrep_scan.py`: `p/java` + `p/owasp-top-ten` 룰셋으로 `data/processed/<category>/sources/`를 스캔해 JSON+SARIF로 저장 (Windows cp949 콘솔에서 SARIF에 포함된 유니코드 문자가 깨지는 걸 막으려 `PYTHONUTF8=1` 강제 설정함). `--category` 인자로 sqli/xss 등 어떤 카테고리든 재사용 가능 (처음부터 일반화되어 있었음)
- `scripts/evaluate_semgrep.py` (구 `evaluate_semgrep_sqli.py`, sqli 전용 → 일반화하며 이름도 변경): semgrep JSON 결과 중 `--category`에 해당하는 CWE 관련 finding만 걸러서 `*_cases.csv` 정답 라벨과 매칭 → Precision/Recall/F1 계산. 카테고리→CWE 번호 매핑(`CATEGORY_TO_CWE`)은 `download_owasp_benchmark.py`와 동일한 값을 사용. p/java, p/owasp-top-ten에는 여러 취약점 룰이 섞여 있어서 반드시 해당 CWE 태그로 필터링해야 공정한 비교가 됨
- `scripts/run_llm_only_sqli.py` (**2026-08-25 카테고리 일반화 완료** — 파일명은 하위 호환을 위해 유지): Claude API(`claude-sonnet-5`)만으로 `--category` 취약점 여부 판단. **정적분석 결과는 절대 프롬프트에 포함하지 않음**(단독 방식 간 공정 비교를 위해). 시스템/유저 프롬프트를 `CATEGORY_TO_CWE`+`CATEGORY_TO_NAME`으로 카테고리별 동적 생성(`build_system_prompt`/`build_user_prompt`). `output_format`(Pydantic `VulnJudgment`, 구 `SqliJudgment`)으로 `{vulnerable, confidence, reasoning}` 구조 강제, 레이트리밋/5xx는 지수 백오프 재시도. `--mock`으로 실제 API 없이 결정론적 가짜 응답을 생성해 파이프라인만 검증 가능
- `scripts/evaluate_llm_sqli.py` (2026-08-25 `--category` 리포트 제목 일반화): `evaluate_semgrep.py`와 동일 패턴으로 LLM 예측 vs 정답 라벨 Precision/Recall/F1 계산. API 실패로 판단이 없는 케이스는 지표 계산에서 제외하고 별도 카운트
- `scripts/merge_hybrid.py` (UC4 통합 로직): `evaluate_semgrep.py`가 만든 `semgrep_predictions.csv`와 `run_llm_only_sqli.py`가 만든 `llm_predictions.json`을 `test_name` 기준으로 매칭. **통합 규칙은 `--rule`로 선택** (Ablation에서 나란히 비교하려고 둘 다 유지):
  - `cascade` (**기본값**) — "Semgrep이 제안하고 LLM이 검증한다". Semgrep 미탐지 → `low`(LLM 심사 안 함) / Semgrep 탐지+LLM도 취약 → `high` / Semgrep 탐지+LLM이 confidence≥`--reject-threshold`로 안전 확신 → `filtered`(오탐으로 기각) / 그 외 → `medium`(보수적 유지). 설계 근거는 아래 "통합 규칙 재설계 근거" 참고
  - `or` — 기존 방식(한쪽이라도 탐지하면 취약). 비교용 베이스라인으로 남겨둠
  - 티어→최종예측 매핑은 `tier_to_predicted()` 한 곳에서만 정의(규칙이 흩어지는 걸 방지). `--category`로 sqli/xss/cmdi/pathtraver 4개 카테고리 모두 실측 완료(2026-08-25)
- `scripts/evaluate_hybrid.py`: `merge_hybrid.py` 산출물로 하이브리드 방식 Precision/Recall/F1 계산 + **티어별 TP/FP/FN/TN 분포**를 리포트. cascade일 때는 "LLM 필터 효과"(기각 건수, 오탐 제거 성공 vs 정탐 손실, **기각 정확도**)를 따로 출력 — 필터가 실제로 이득이었는지 판단하는 핵심 지표. 티어 정의는 `merge_hybrid.TIER_ORDER`를 import해서 한 곳에서만 관리
- `scripts/dataset_split.py` (신규): 벤치마크 케이스를 train/held-out으로 **결정론적·층화 분할**. 하이퍼파라미터(`--reject-threshold`, 향후 LR/보정계수)를 평가에 쓰는 데이터에서 고르면 누수이므로, 튜닝은 train에서만 하고 최종 지표는 held-out에서만 보고하기 위한 것. `hashlib.sha256`로 배정(파이썬 `hash()`는 프로세스마다 salt가 달라 재현 불가) → 실행할 때마다 같은 분할이 나오고, 케이스가 추가돼도 기존 배정이 안 흔들림. 라벨별로 seed를 분리해 양성비율 보존. `load_split()`/`filter_by_split()`으로 다른 스크립트에서 import 가능
- `scripts/calibrate_confidence.py` (신규): LLM confidence의 보정 상태(ECE/MCE/signed gap)를 측정하고 캐스케이드 `--reject-threshold`를 튜닝. **보정 대상은 "취약할 확률"이 아니라 "LLM 자신의 판정이 맞을 확률"** — 캐스케이드가 confidence를 그 용도로 쓰기 때문. `--split`은 기본이 `train`이고 `heldout`은 명시해야만 열리게 해서 누수를 구조적으로 막음(held-out 사용 시 경고 배너 출력). `--bin-mode equal-width`(표준 ECE 정의)와 `quantile`(confidence가 0.9+에 몰려 있어 실질 해상도가 높음) 둘 다 지원. `--sweep`으로 threshold별 F1·기각정확도·정탐손실 트레이드오프를 표로 출력, `--threshold`로 단일 값 최종 평가. 캐스케이드 판정은 `merge_hybrid.confidence_tier_cascade`를 import해 재사용(규칙 이중 구현 방지)
- `scripts/compare_rules_heldout.py` (신규): held-out 분할에서 4방식(Semgrep 단독/LLM 단독/OR/cascade)을 나란히 비교하는 **Ablation 최종 산출물**. 전체 데이터로 계산하면 튜닝에 쓴 train이 섞여 낙관 편향되므로 held-out에서만 보고한다(`--split`은 기본이 heldout). cascade threshold는 `TUNED_THRESHOLDS`에 카테고리별 튜닝값을 두되 `--threshold`로 통일 가능. 판정 로직은 `merge_hybrid`의 `confidence_tier_or`/`confidence_tier_cascade`를 import해 재사용하고, 케이스 로딩은 `calibrate_confidence.load_cases`를 재사용(중복 구현 방지). 산출물은 `data/results/rule_comparison_heldout.json`
- `scripts/measure_grounding.py` (신규, 2026-08-26 2차 버그 수정): LLM `reasoning`이 **실제로 존재하는 코드를 근거로 들었는지** 검증해 환각률 측정. P/R/F1만으로는 "정답을 맞혔지만 근거가 날조된" 경우를 구분할 수 없어서, 프로젝트 핵심 주장(grounding→환각 억제)을 정량화하려면 이 지표가 필요함. reasoning에서 인용(`line` 라인번호 / `ident` 백틱 코드 / `call` 메서드호출 / `type` 타입명)을 추출해 원본 `.java`와 대조. **권고문 제외 처리가 핵심** — "PreparedStatement를 썼어야 함"은 코드에 대한 주장이 아니라 제안이므로 인용으로 세면 안 됨(안 걸러내면 올바른 보안 권고가 전부 환각으로 잘못 집계됨). `RECOMMENDATION_MARKERS`에는 **부재 주장**("~가 전혀 없으며/없이/없으므로/없습니다")도 포함 — "코드가 X를 포함한다"는 주장이 아니라 정반대이므로 같은 이유로 제외. `STOPWORDS`에는 취약점 이름 자체(`traversal`)나 공격 페이로드 예시(`alert`, `script`, `drop`, `table` 등 `<script>alert(1)</script>`류)도 포함 — grounded 4카테고리 실측 감사에서 전수 확인 후 추가함(자세한 발견 경위는 10장 "`run_llm_grounded.py` 작성 + 4카테고리 grounded 실측" 절 참고). `type`은 일반론 언급이 잦아 기본 종합지표에서 제외(`--include-types`로 포함). `--compare-json`으로 grounding 제공/미제공 두 arm 비교
- `scripts/run_llm_grounded.py` (신규): `run_llm_only_sqli.py`(단독 방식, grounding 미제공)와 별도로 분리한 **하이브리드 실험용** 경로. Semgrep 탐지 결과(해당 CWE로 필터링된 finding만, `evaluate_semgrep.is_category_finding`과 동일 기준 재사용)를 프롬프트에 컨텍스트로 포함하되 "Semgrep은 오탐/미탐 가능하니 그대로 따르지 말라"고 명시. `--limit`은 "이번 실행에서 새로 호출할 건수"이고 이미 결과 있는 `test_name`은 건너뜀(이어하기 지원, 중복 과금 방지) — 파일럿 30건으로 실측 단가 확인 후 전체 실행하는 예산 관리 워크플로우를 위해 설계함. 각 응답의 `usage`(입력/출력 토큰)를 결과에 함께 저장해 실측 비용 계산 가능. `max_tokens=2048`(ungrounded의 1024보다 큼 — grounded 프롬프트가 "Semgrep 결과에 동의/반박" 논의까지 요구해 reasoning이 길어지고, 1024에서는 1,478건 중 49건이 JSON 중간에 잘리는 문제가 실측으로 확인됨)
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

### 4방식 × 4카테고리 종합 실측 비교 — Claude Sonnet 5 실제 API (2026-08-25, 전체 1,478건, 실패 0건)

| 카테고리 | 방식 | TP / FP / FN / TN | Precision | Recall | F1-score |
|---|---|---|---|---|---|
| **SQLi** (504건) | Semgrep 단독 | 234 / 143 / 38 / 89 | 0.6207 | 0.8603 | 0.7211 |
| | LLM 단독 | 272 / 135 / 0 / 97 | 0.6683 | 1.0000 | **0.8012** |
| | 하이브리드 (OR) | 272 / 199 / 0 / 33 | 0.5775 | 1.0000 | 0.7322 |
| | 하이브리드 (cascade) | 234 / 79 / 38 / 153 | 0.7476 | 0.8603 | 0.8000 |
| **XSS** (455건) | Semgrep 단독 | 202 / 108 / 44 / 101 | 0.6516 | 0.8211 | 0.7266 |
| | LLM 단독 | 246 / 78 / 0 / 131 | 0.7593 | 1.0000 | **0.8632** |
| | 하이브리드 (OR) | 246 / 153 / 0 / 56 | 0.6165 | 1.0000 | 0.7628 |
| | 하이브리드 (cascade) | 202 / 33 / 44 / 176 | 0.8596 | 0.8211 | 0.8399 |
| **Command Injection** (251건) | Semgrep 단독 | 112 / 96 / 14 / 29 | 0.5385 | 0.8889 | 0.6707 |
| | LLM 단독 | 126 / 84 / 0 / 41 | 0.6000 | 1.0000 | **0.7500** |
| | 하이브리드 (OR) | 126 / 113 / 0 / 12 | 0.5272 | 1.0000 | 0.6904 |
| | 하이브리드 (cascade) | 112 / 67 / 14 / 58 | 0.6257 | 0.8889 | 0.7344 |
| **Path Traversal** (268건) | Semgrep 단독 | 120 / 106 / 13 / 29 | 0.5310 | 0.9023 | 0.6685 |
| | LLM 단독 | 133 / 74 / 0 / 61 | 0.6425 | 1.0000 | **0.7824** |
| | 하이브리드 (OR) | 133 / 121 / 0 / 14 | 0.5236 | 1.0000 | 0.6873 |
| | 하이브리드 (cascade) | 120 / 59 / 13 / 76 | 0.6704 | 0.9023 | 0.7692 |

**핵심 발견 (4개 카테고리 전부 일관됨):**

1. **LLM 단독의 Recall이 4개 카테고리 전부 정확히 1.0000** — 1,478건 중 놓친 취약점(FN)이 단 한 건도 없음. Semgrep 단독은 카테고리마다 Recall이 0.82~0.90으로 흔들리는 반면, LLM은 예외 없이 전부 잡아냄
2. **F1 최고 방식은 4개 카테고리 모두 LLM 단독** (0.75~0.86) — cascade가 근소하게 뒤따르고(sqli는 사실상 동률), OR과 Semgrep 단독이 하위권. 다만 F1 하나로 "최선"을 정하는 건 성급함 — 아래 "해석" 참고
3. **캐스케이드의 기각 정확도가 4개 카테고리 전부 1.0000** — 기각 건수는 sqli 64 / xss 75 / cmdi 29 / pathtraver 47, 도합 **215건을 기각했는데 정탐 손실이 단 한 건도 없음**. 지난 세션 시뮬레이션(LLM 특이도 0.9 가정 시 F1 0.80~0.86 예측)을 실측이 그대로 재현하거나 상회함 — 특히 pathtraver(0.669→0.7692)와 cmdi(0.671→0.7344)처럼 Semgrep이 가장 약했던 카테고리에서 캐스케이드 이득이 가장 크다는 지난 세션의 예측이 실측으로 확인됨
4. **OR 룰은 4개 카테고리 모두 최하위 F1** — 이미 완벽한 LLM 단독 Recall에 Semgrep의 FP를 얹기만 해서 Precision만 깎임. "Semgrep의 우도비(LR-가 LR+보다 강함)로 볼 때 OR은 증거 방향이 거꾸로"라는 지난 세션 가설이 4개 카테고리 전부에서 재확인됨
5. **캐스케이드의 구조적 한계도 4개 카테고리 공통** — Recall이 항상 Semgrep 단독과 정확히 같음(캐스케이드가 Semgrep 미탐지를 재심사하지 않으므로 FN이 Semgrep의 FN을 그대로 물려받음). 이 상한을 베이지안 로그오즈 결합이 풀 수 있는지가 다음 단계의 핵심 질문

**해석 — "LLM 단독이 다 이겼다"로 단순화하면 안 되는 이유:** F1은 Precision·Recall에 동일 가중치를 주는데, 실서비스(PR 코멘트 자동 게시)에서는 오탐 하나가 사용자 신뢰를 깎는 비용이 미탐 하나를 놓치는 비용과 다를 수 있다. cascade는 LLM 단독보다 Precision이 항상 더 높다(예: xss 0.7593→0.8596, cmdi 0.6000→0.6257, pathtraver 0.6425→0.6704) — "오탐을 줄이는 게 최우선"인 운영 맥락이라면 F1이 근소하게 낮아도 cascade가 나은 선택일 수 있다. 반대로 "취약점을 하나도 놓치면 안 된다"는 맥락이면 Recall 1.0000인 LLM 단독(또는 OR)이 유리하다. 이 트레이드오프를 어느 지표로 대표할지(F-beta, 비용 가중 지표 등)는 발표/리포트에서 명시적으로 정해야 할 지점.

### Grounding precision 실측 결과 — LLM 단독(ungrounded), SQLi 504건 (다른 3개 카테고리는 미측정)

| 지표 | 값 |
|---|---|
| 전체 인용 수 | 877 (ident 25 + call 852) |
| 검증 성공 | 875 |
| **Grounding precision** | **0.9977** |
| 환각률 | 0.0023 |

잔여 실패 2건(`index0`/`index1`, 단일 케이스)은 LLM이 리스트 인덱스를 설명한 표현이지 진짜 날조가 아님 — 즉 실질 환각률은 사실상 0에 수렴. `line` 인용이 0건인 건 버그가 아니라 시스템 프롬프트가 라인 번호가 아닌 변수/데이터흐름 서술을 요구하기 때문(`run_llm_only_sqli.py`의 `build_system_prompt()` 참고).

(위 표의 산출 과정에서 `measure_grounding.py`의 인용 추출 정규식 버그를 발견해 수정함 — "false positive(설명)"류 괄호 서술을 코드 호출로 오인식하던 문제. 892건 인용을 전수 확인해 STOPWORDS에 반영했고, 수정 전 환각률은 0.0191이었음. 이 수치는 4카테고리 grounded 실측 이전의 1차 수정 결과이며, 2차 수정 후 재측정한 최종값은 아래 표 참고.)

### `run_llm_grounded.py` 작성 + 4카테고리 grounded 실측 (2026-08-26)

**실행**: `run_llm_grounded.py` 신규 작성 — Semgrep 탐지 결과(해당 CWE 카테고리로 필터링된 finding만, 없으면 "미탐지"임을 명시)를 프롬프트에 컨텍스트로 포함하되 "Semgrep은 오탐/미탐 모두 가능하니 그대로 따르지 말고 스스로 판단하라"고 명시. `run_llm_only_sqli.py`는 절대 수정하지 않고 별도 파일로 분리(단독 방식 공정 비교 유지).

SQLi 30건 파일럿으로 건당 단가 확인(~$0.0095~0.0099/건) 후 전체 1,478건(잔여 1,448건) 실행. 예산 $17.94 중 **최종 $15.08 사용**(잔여 $2.86). 1,478건 전부 완료, 최종 실패 0건.

- **max_tokens 버그 발견·수정**: grounded 프롬프트는 "Semgrep 결과에 동의/반박" 논의까지 요구해 ungrounded보다 reasoning이 길어짐 — 1차 실행에서 1024 토큰 한도에 걸려 49건(3.3%)이 JSON 중간에 잘려 파싱 실패. 2048로 올려 49건 전부 재시도 성공(추가 비용 약 $0.62, 예산 내)

- **`measure_grounding.py` 2차 버그 수정**: grounded 결과로 처음 비교했을 때 4개 카테고리 중 3개에서 "grounding이 오히려 환각을 늘림"으로 나와 전수 감사함 — 실패 사례 전부가 인용 추출기의 오탐이었음(진짜 코드 날조 0건):
  - 취약점 이름 자체가 오인식됨: `Path Traversal(CWE-22)` → `Traversal(` 을 메서드 호출로 오인
  - 서술적 괄호 부연: `propagator(설명)`, `envp(환경변수)`, `shell(-c)` 등
  - **공격 페이로드 예시**를 코드 인용으로 오인: `<script>alert(1)</script>`, `` `; DROP TABLE users; --` `` (grounded 프롬프트가 Semgrep 근거를 반박/동의하며 예시를 드는 경우가 늘어 이 패턴이 급증)
  - **부재 주장**을 존재 주장으로 오인: "FilenameUtils.getName() 등의 정규화 로직이 전혀 없으며/없이/없으므로/없습니다"처럼 특정 API가 **없다**는 문장은 코드가 그걸 포함한다는 주장이 아닌데도 인용으로 집계됨 — 어미가 다양해("전혀 없으며"/"없이"/"없으므로"/"없습니다") 하나씩 패턴을 넓혀야 했음

  `STOPWORDS`와 부재 주장 필터(`RECOMMENDATION_MARKERS`에 "전혀"/"없으므로"/"없이"/"없습니다" 등 추가)를 확장해 재측정. **수정 전후 판정이 완전히 뒤집힘** — 이 버그가 없었다면 "grounding이 환각을 늘린다"는 잘못된 결론을 리포트에 실을 뻔했음.

**Grounding precision 최종 비교 (4카테고리, --compare-json)**

| 카테고리 | ungrounded precision (n) | grounded precision (n) |
|---|---|---|
| SQLi | 0.9969 (653) | **1.0000** (1064) |
| XSS | 0.9965 (866) | **1.0000** (1294) |
| CMDI | 0.9933 (447) | **1.0000** (697) |
| PathTraversal | 0.9964 (277) | **1.0000** (589) |

**4개 카테고리 전부에서 grounded 환각률이 0.0000으로, 핵심 주장("grounding이 환각을 억제한다")과 방향이 일치**. 다만 두 가지 유보 사항:
1. ungrounded의 기준선 자체가 이미 0.9933~0.9969로 매우 높아 개선 여지가 원래 작았음(위 절에서 이미 예고한 우려)
2. 부재 주장 필터를 넓히면서 두 arm 모두 "판단 불가(근거 미제시)"로 빠지는 케이스가 늘어 총 인용 수가 줄었음(예: xss 1843→1294) — 정밀도 자체는 남은 인용 중 검증 성공 비율이라 왜곡되지 않지만, "grounded가 근거를 더 많이/정확히 댄다"는 강한 주장을 하려면 인용 수 자체의 감소도 함께 언급해야 공정함

**참고 — grounded를 "환각률"이 아니라 단독 분류기 성능(P/R/F1)으로 봤을 때**: 위 표는 reasoning의 근거가 실제 코드에 있는지(환각률)만 측정한 것이고, 최종 `vulnerable` 판정 자체의 정오답 성능은 별개 지표다. 저장된 예측과 정답 라벨을 직접 대조하면:

| 카테고리 | arm | TP/FP/FN/TN | Precision | Recall | F1 |
|---|---|---|---|---|---|
| SQLi | ungrounded | 272/135/0/97 | 0.6683 | 1.0000 | 0.8012 |
| | grounded | 272/163/0/69 | 0.6253 | 1.0000 | 0.7694 |
| XSS | ungrounded | 246/78/0/131 | 0.7593 | 1.0000 | 0.8632 |
| | grounded | 246/100/0/109 | 0.7110 | 1.0000 | 0.8311 |
| CMDI | ungrounded | 126/84/0/41 | 0.6000 | 1.0000 | 0.7500 |
| | grounded | 126/104/0/21 | 0.5478 | 1.0000 | 0.7079 |
| PathTraversal | ungrounded | 133/74/0/61 | 0.6425 | 1.0000 | 0.7824 |
| | grounded | 133/93/0/42 | 0.5885 | 1.0000 | 0.7409 |

Recall은 양쪽 다 1.0000으로 동일하지만, **4개 카테고리 전부에서 grounded가 ungrounded보다 Precision이 낮다**(FP가 더 많음). 즉 grounding이 "근거의 사실성"(환각률)은 개선해도, 최종 판정의 정확도(P/R/F1)는 오히려 악화시켰다. 교차 파일 헬퍼 오판 분석(아래 절)에서 본 "Semgrep 신호·벤치마크 의도를 의식해 자기 판단을 뒤집는" 경향과 같은 방향이다.

### 교차 파일 헬퍼 오판 — grounding이 못 고친 것 (2026-08-26, 핵심 발견)

**질문**: 3단계 전 세션에서 발견한 "LLM이 `SeparateClassRequest.getTheValue()`가 상수 `"bar"`를 반환하는 걸 모르고 오탐하는" 패턴(예: `BenchmarkTest00052`)이, Semgrep 결과를 grounding으로 주면 고쳐지는가?

**답: 아니다.** `getTheValue()` 헬퍼를 쓰는 안전 케이스(4카테고리 합산 142건)를 전수 대조한 결과:

| 결과 | 건수 |
|---|---|
| 고쳐짐 (ungrounded 오답 → grounded 정답) | **0건** |
| 여전히 오답 (양쪽 다 틀림) | 110건 |
| 원래 정답 (양쪽 다 맞음) | 24건 |
| **악화** (ungrounded 정답 → grounded 오답) | **8건** |

**원인**: `run_llm_grounded.py`가 프롬프트에 넣는 grounding은 **Semgrep의 탐지 여부(있음/없음)뿐**, 헬퍼 클래스의 실제 소스 코드가 아니다. `BenchmarkTest00052`의 grounded reasoning을 직접 보면:

> "SeparateClassRequest.getTheValue(...) 호출 결과이며(**대부분의 OWASP Benchmark 케이스에서 이는 request parameter 값을 그대로 반환**), ..."

LLM은 헬퍼 파일을 볼 수 없으니 **OWASP Benchmark에 대한 사전 학습 지식으로 "이런 이름의 메서드는 보통 이렇게 동작한다"고 추정**하고 있다 — 정확히 이 케이스에서는 틀린 추정. Semgrep의 신호(sqli/xss는 이 패턴을 미탐지 = "안전"이라는 올바른 신호)를 grounding으로 줘도 LLM이 자기 소스코드 기반 추론을 우선시해 뒤집지 못했다. 즉 **"정적분석의 탐지 여부"라는 신호와 "실제로 필요한 정보"(헬퍼의 진짜 구현)는 다른 종류의 정보라서, Semgrep 신호만으로는 이 클래스의 오판을 구조적으로 고칠 수 없다.**

부수 발견 — 악화 8건 중 1건(`sqli/BenchmarkTest02735`)은 grounding 문제가 아니라 **스키마 필드 순서 아티팩트**로 보임: `confidence=0.15`(매우 낮음)인데 `vulnerable=true`이고, reasoning 전체가 "실제로는 익스플로잇 불가능", "실질적인 취약점은 없다고 판단됩니다"로 끝남 — 즉 모델이 스스로 안전하다고 결론 내렸는데 최종 필드는 취약으로 나옴. `VulnJudgment` 스키마가 `vulnerable`(bool)을 `reasoning`(str)보다 먼저 요구해서, 구조화 출력이 reasoning을 다 쓰기 전에 verdict를 먼저 커밋하는 구조이기 때문일 가능성이 높다(다만 118건 대조 중 이 패턴은 1건뿐이라 지배적 원인은 아님). **향후 스키마를 reasoning-먼저-verdict-나중 순서로 바꾸면 개선될 수 있는 지점** — 다음 세션 과제로 남김.

**결론 및 향후 방향**: grounding의 정의를 "Semgrep 탐지 여부"에서 "관련 파일의 실제 소스(헬퍼 클래스 등)"로 넓히는 실험이 다음 단계로 유효함. 다만 예산($2.86 남음)과 범위(어떤 파일을 "관련"으로 볼지 자동 판단 필요) 문제로 이번 세션에서는 착수하지 않음.

### 통합 규칙 재설계 근거 — FP 원인 분석 (2026-08-05)

**Semgrep FP의 실제 원인** (추측이 아니라 벤치마크 케이스를 직접 열어 확인):

1. **소스 과대추정 (룰 수준 차이)** — OWASP Benchmark 헬퍼 `SeparateClassRequest.getTheValue()`는 요청을 무시하고 상수 `"bar"`를 반환하는 **안전 소스**(헬퍼 원본 주석에 `This method is a 'safe' source.`라고 명시). 그런데 이걸 sqli/xss 룰은 올바르게 무시(97건 전부 TN)하는 반면 **cmdi/pathtraver 룰만 오탐**(45건 중 39건, 87%). 결정적 증거는 대조쌍 `cmdi/BenchmarkTest00051` vs `sqli/BenchmarkTest00052` — 소스·전파 구조가 완전히 동일하고 **싱크만 다른데** 전자는 FP, 후자는 TN. "sqli 룰이 `prepareCall`을 싱크로 안 봐서 우연히 통과한 것"이라는 대안 가설은 배제됨(진짜 취약한 `prepareCall` 케이스는 TP=29/FN=2로 정상 탐지). **추가 실험: 헬퍼 소스를 같은 디렉토리에 넣고 재스캔해도 finding이 그대로 남음** → 데이터 준비 실수가 아니라 Semgrep OSS의 파일 단위 taint 분석의 한계(교차 파일 해석은 Pro Engine 기능). 즉 "헬퍼를 복사해서 고치는" 방향은 효과 없음
2. **죽은 분기 (상수 폴딩 부재)** — `int num=86; if ((7*42)-num > 200) bar="상수"; else bar=param;` 처럼 조건이 **항상 참**이라 taint 대입이 죽은 코드인 케이스(294-86=208>200). 오탐률 sqli 89.6% / xss 73.3% / cmdi 91.3% / pathtraver 90.6% — **카테고리 격차의 원인은 아니고(sqli도 똑같이 당함) 전 카테고리 공통 천장**이지만 절대 건수로는 최대 FP 유발원
3. **switch문** — cmdi 100%(18/18), pathtraver 92.9% vs sqli 62.5%, xss 75.0%

**격차의 정체는 특이도(TNR)**: 네 카테고리 양성비율이 50~54%로 거의 같으므로(기저율 차이 아님) Precision 격차는 전적으로 TNR 차이 — sqli 38.4% / xss 48.3% / **cmdi 23.2% / pathtraver 21.5%**. cmdi/pathtraver는 전체 파일의 83~84%에 경보를 울림("거의 항상 발화").

**Semgrep을 증거로 봤을 때의 우도비** (캐스케이드 설계의 직접 근거):

| 카테고리 | LR+ (탐지 시) | LR− (미탐지 시) |
|---|---|---|
| sqli | 1.40 | 0.36 |
| xss | 1.59 | 0.37 |
| cmdi | 1.16 | 0.48 |
| pathtraver | 1.15 | 0.46 |

→ **Semgrep의 "침묵"이 "경보"보다 2~3배 정보량이 많다.** 기존 OR 룰은 정확히 반대로, 약한 증거(LR+ 1.15)를 확정 판정으로 승격시키고 강한 증거(미탐지)는 LLM이 울리면 버렸음 — 이것이 Precision이 무너진 구조적 이유. 캐스케이드는 미탐지를 최종 판정으로 받아들이고(`low`) 탐지분만 재심사하도록 뒤집은 것.

**캐스케이드 기대 효과** (LLM 민감도 0.9 가정, 특이도 t별 F1 시뮬레이션):

| 카테고리 | Semgrep 단독 F1 | t=0.5 | t=0.7 | t=0.9 |
|---|---|---|---|---|
| sqli | 0.721 | 0.760 | 0.802 | 0.848 |
| xss | 0.727 | 0.755 | 0.790 | 0.829 |
| cmdi | 0.671 | 0.734 | 0.789 | **0.853** |
| pathtraver | 0.669 | 0.735 | 0.792 | **0.859** |

Semgrep이 가장 약한 카테고리에서 이득이 가장 큼(걸러낼 오탐이 많으므로). 손익분기는 LLM 특이도 약 0.3~0.35.

### Confidence 보정(calibration) 및 threshold 튜닝 결과 (2026-08-25)

`scripts/calibrate_confidence.py`로 측정. **튜닝·탐색은 train 분할에서만 수행하고, held-out은 튜닝에 쓰지 않았고, 최종 확인용으로 열었다(이후 사후 확인 1회 추가 — 아래 '통합 규칙 최종 비교' 절의 재열람 기록 참고)** (`dataset_split.py`의 결정론적 층화 분할, train 약 30%).

**보정 상태 — train 분할, equal-width 10구간**

측정 대상은 "취약할 확률"이 아니라 **"LLM 자신의 판정이 맞을 확률"** — 캐스케이드가 confidence를 "LLM의 '안전' 판정을 믿고 Semgrep 경보를 기각할지"에 쓰기 때문.

| 카테고리 | train n | 평균 confidence | 실제 판정 정확도 | ECE | MCE | signed gap |
|---|---|---|---|---|---|---|
| SQLi | 140 | 0.9261 | 0.7357 | 0.2050 | 0.6500 | +0.1904 |
| XSS | 149 | 0.9191 | 0.8389 | **0.1200** | 0.1485 | +0.0801 |
| CMDI | 77 | 0.9206 | 0.6364 | **0.2843** | 0.6800 | +0.2843 |
| PathTraversal | 78 | 0.9026 | 0.7436 | 0.1590 | 0.7500 | +0.1590 |

**4개 카테고리 전부 과신(overconfident)** — signed gap이 모두 양수. 정도는 카테고리마다 다르며 **CMDI가 가장 심하고(ECE 0.284) XSS가 가장 양호**(0.120). 이는 Semgrep 성능 순서(cmdi/pathtraver가 약하고 xss가 강함)와 대체로 일치 — 어려운 카테고리에서 LLM도 함께 과신한다.

⚠️ confidence가 0.9 이상에 85~90%가 몰려 있어 equal-width 구간은 대부분 비어 있다(`--bin-mode quantile`로 분포 기반 재확인 가능). 또 cmdi/pathtraver는 train n이 77~78로 작아 구간별 추정이 불안정하다 — MCE가 0.65~0.75로 큰 것도 소수 표본 구간(1~3건) 때문이므로 MCE는 과대해석하지 말 것.

**threshold 스윕 — train 분할, 캐스케이드 F1 및 기각정확도/Recall 트레이드오프**

| 카테고리 | F1 최대 구간 | 선택한 threshold | train F1 | 기존 기본값(0.7) 대비 |
|---|---|---|---|---|
| SQLi | 0.00 ~ 0.85 | 0.85 | 0.8024 | **+0.0000** |
| XSS | 0.00 ~ 0.80 | 0.80 | 0.8252 | **+0.0000** |
| CMDI | 0.00 ~ 0.75 | 0.75 | 0.7045 | **+0.0000** |
| PathTraversal | 0.00 ~ 0.85 | 0.85 | 0.7843 | **+0.0000** |

**핵심 발견 — threshold 튜닝의 실익이 없다.** 4개 카테고리 전부에서 **threshold를 0.00까지 낮춰도 정탐 손실(rejected_vuln)이 0건**이었다. 즉 LLM이 "안전"이라고 판정한 Semgrep 탐지 건은 train 분할에서 **하나도 빠짐없이 실제로 안전**했고, 그래서 기각을 많이 할수록(threshold를 낮출수록) Precision만 오르고 Recall은 그대로다. F1 최대 구간이 0.00부터 넓게 형성되며 **기존 하드코딩 기본값 0.7이 이미 그 최적 구간 안에 있다**. 위 표의 선택값은 "F1 동률 구간에서 가장 보수적인(높은) 값"을 고른 것이라 실질 성능 차이가 없다.

threshold가 성능에 영향을 주기 시작하는 지점은 0.90 이상(기각 건수가 급감)이며, 0.95 이상에서는 기각이 0건이 되어 캐스케이드가 사실상 Semgrep 단독으로 퇴화한다.

**held-out 최종 결과 — 위에서 결정한 threshold를 딱 한 번 적용**

| 카테고리 | threshold | held-out n | TP / FP / FN / TN | Precision | Recall | F1 | 기각 | 기각정확도 |
|---|---|---|---|---|---|---|---|---|
| SQLi | 0.85 | 364 | 167 / 58 / 26 / 113 | 0.7422 | 0.8653 | 0.7990 | 49 | **1.0000** |
| XSS | 0.80 | 306 | 143 / 25 / 28 / 110 | 0.8512 | 0.8363 | 0.8437 | 44 | **1.0000** |
| CMDI | 0.75 | 174 | 81 / 46 / 9 / 38 | 0.6378 | 0.9000 | 0.7465 | 19 | **1.0000** |
| PathTraversal | 0.85 | 190 | 80 / 40 / 10 / 60 | 0.6667 | 0.8889 | 0.7619 | 34 | **1.0000** |

**held-out에서도 기각 정확도 1.0000이 4개 카테고리 전부 재현됐다** — 총 146건을 기각하면서 정탐 손실 0건. train에서 관찰한 "LLM의 안전 판정은 (이 벤치마크에서) 완벽하게 신뢰할 수 있다"는 패턴이 미개봉 데이터에서도 유지된다는 뜻으로, 캐스케이드 설계의 핵심 전제가 검증된 셈이다. F1도 train 값과 근접해(예: sqli 0.8024→0.7990, xss 0.8252→0.8437) 과적합 징후가 없다.

**해석과 한계**

- confidence는 과신 편향이 뚜렷하지만(ECE 0.12~0.28), **캐스케이드가 confidence를 임계값 비교로만 쓰기 때문에 이 편향이 성능에 거의 영향을 주지 않는다.** LLM의 이진 판정(vulnerable=False)이 정확하다면 confidence 값 자체는 부차적이다.
- 반대로 **베이지안 로그오즈 결합에는 이 과신이 치명적**이다. 로그오즈 합산은 confidence를 확률로 직접 쓰므로, ECE 0.28짜리 값을 그대로 넣으면 사후확률이 왜곡된다. 착수한다면 Platt/isotonic 보정이 반드시 선행되어야 하고, 보정 계수도 train 분할에서만 추정해야 한다.
- 이 벤치마크(OWASP Benchmark)는 안전 케이스가 "죽은 분기/상수 헬퍼" 같은 정형화된 패턴이라 LLM이 판별하기 쉬운 편이다. 실제 오픈소스 코드에서도 기각 정확도가 1.0을 유지할지는 별개 문제이며, 3단계 실사례 검증에서 확인이 필요하다.

### 통합 규칙 최종 비교 — held-out 분할 (2026-08-25, Ablation 최종 산출물)

`scripts/compare_rules_heldout.py`로 산출. **튜닝에 쓰지 않은 held-out 분할에서만** 4방식을 나란히 적용했다. cascade의 threshold는 train에서 고른 카테고리별 값(sqli 0.85 / xss 0.80 / cmdi 0.75 / pathtraver 0.85).

| 카테고리 | 방식 | TP / FP / FN / TN | Precision | Recall | F1 |
|---|---|---|---|---|---|
| **SQLi** (364건) | Semgrep 단독 | 167 / 107 / 26 / 64 | 0.6095 | 0.8653 | 0.7152 |
| | LLM 단독 | 193 / 98 / 0 / 73 | 0.6632 | 1.0000 | 0.7975 |
| | 하이브리드 (OR) | 193 / 147 / 0 / 24 | 0.5676 | 1.0000 | 0.7242 |
| | 하이브리드 (cascade) | 167 / 58 / 26 / 113 | **0.7422** | 0.8653 | **0.7990** |
| **XSS** (306건) | Semgrep 단독 | 143 / 69 / 28 / 66 | 0.6745 | 0.8363 | 0.7467 |
| | LLM 단독 | 171 / 54 / 0 / 81 | 0.7600 | 1.0000 | **0.8636** |
| | 하이브리드 (OR) | 171 / 99 / 0 / 36 | 0.6333 | 1.0000 | 0.7755 |
| | 하이브리드 (cascade) | 143 / 25 / 28 / 110 | **0.8512** | 0.8363 | 0.8437 |
| **CMDI** (174건) | Semgrep 단독 | 81 / 65 / 9 / 19 | 0.5548 | 0.9000 | 0.6864 |
| | LLM 단독 | 90 / 56 / 0 / 28 | 0.6164 | 1.0000 | **0.7627** |
| | 하이브리드 (OR) | 90 / 75 / 0 / 9 | 0.5455 | 1.0000 | 0.7059 |
| | 하이브리드 (cascade) | 81 / 46 / 9 / 38 | **0.6378** | 0.9000 | 0.7465 |
| **PathTraversal** (190건) | Semgrep 단독 | 80 / 74 / 10 / 26 | 0.5195 | 0.8889 | 0.6557 |
| | LLM 단독 | 90 / 54 / 0 / 46 | 0.6250 | 1.0000 | **0.7692** |
| | 하이브리드 (OR) | 90 / 88 / 0 / 12 | 0.5056 | 1.0000 | 0.6716 |
| | 하이브리드 (cascade) | 80 / 40 / 10 / 60 | **0.6667** | 0.8889 | 0.7619 |

**held-out F1 요약**

| 카테고리 | Semgrep 단독 | LLM 단독 | OR | cascade | OR→cascade |
|---|---|---|---|---|---|
| SQLi | 0.7152 | 0.7975 | 0.7242 | **0.7990** | +0.0748 |
| XSS | 0.7467 | **0.8636** | 0.7755 | 0.8437 | +0.0681 |
| CMDI | 0.6864 | **0.7627** | 0.7059 | 0.7465 | +0.0407 |
| PathTraversal | 0.6557 | **0.7692** | 0.6716 | 0.7619 | +0.0903 |
| **평균** | 0.7010 | **0.7983** | 0.7193 | 0.7878 | **+0.0685** |

**결론:**

1. **cascade가 OR을 4개 카테고리 전부에서 이긴다** (F1 +0.041 ~ +0.090, 평균 +0.0685). 트레이드오프 구조가 일관됨 — Precision +0.09~+0.22를 얻고 Recall −0.10~−0.16을 내준다. OR은 Semgrep의 오탐을 그대로 더하기만 해서 Semgrep 단독보다는 낫지만 LLM 단독보다 못하다.
2. **F1만 보면 LLM 단독이 4개 중 3개에서 최고**(평균 0.7983 vs cascade 0.7878). 차이는 평균 0.0105로 작다.
3. **Precision만 보면 cascade가 4개 전부 최고** — LLM 단독 대비 sqli +0.079 / xss +0.091 / cmdi +0.021 / pathtraver +0.042. PR 코멘트를 자동 게시하는 실서비스처럼 오탐 비용이 큰 맥락에서는 cascade가 합리적 선택이고, 취약점 누락 비용이 압도적인 맥락에서는 Recall 1.0000인 LLM 단독이 낫다. **어느 쪽이 "최선"인지는 지표가 아니라 운영 맥락이 정한다** — 발표/리포트에서 이 트레이드오프를 명시적으로 다룰 것.
4. Semgrep 단독은 4개 전부 최하위. 정적분석만으로는 부족하다는 프로젝트 전제가 held-out에서 확인됨.

**held-out 재열람 기록 (튜닝 결정에는 미반영)**: 이후 감사 과정에서, 위 표의 튜닝 threshold 대신 **기본값 0.70을 held-out에 적용했을 때**와 비교하기 위해 held-out을 한 번 더 열었다. sqli/cmdi/pathtraver는 완전히 동일한 결과(TP/FP/FN/TN, F1 전부 일치)였고, xss만 미세한 차이가 있었다 — 0.70: TP=143/FP=24/FN=28/TN=111, F1=0.8462 vs 튜닝값 0.80(위 표): F1=0.8437. 즉 xss는 오히려 **튜닝 전 기본값이 held-out F1이 더 높다**(+0.0025). 이 비교는 사후 확인용으로만 썼고 **threshold를 다시 조정하는 데 쓰지 않았다** — 위 표의 튜닝값(0.85/0.80/0.75/0.85)은 train 분할에서 이미 확정된 값을 그대로 유지한다.

### 향후 과제 — 베이지안 로그오즈 결합 (착수하지 않기로 결정, 2026-08-25)

캐스케이드의 구조적 한계(Semgrep이 놓친 FN을 복구 못 함)를 완화하는 대안으로 **베이지안 로그오즈 결합**을 검토했다. 두 탐지기의 출력을 독립 증거로 보고

```
logit P(취약) = logit(사전확률) + log LR_semgrep[카테고리][발화여부] + log LR_llm[신뢰도구간]
```

로 사후확률을 계산해 신뢰도 티어를 투표 수가 아니라 사후확률 구간으로 재정의하는 방식이다. 카테고리별 우도비(위 "통합 규칙 재설계 근거" 표)를 그대로 주입하면 가중치의 자의성을 피할 수 있다는 장점이 있다.

**착수하지 않기로 한 이유:**

1. **단순 임계값이 이미 최적점 근처였다** — threshold 스윕 결과 F1 최대 구간이 0.00부터 넓게 형성되고 기존 기본값 0.7이 그 안에 있어 튜닝 실익이 0이었다. 결합 함수를 정교화해서 얻을 여지가 크지 않다는 신호다.
2. **confidence의 ECE가 카테고리별 0.12~0.28로 크다** — 로그오즈 합산은 confidence를 확률로 직접 쓰므로, 이 과신을 보정 없이 넣으면 사후확률이 체계적으로 왜곡된다. Platt/isotonic 보정이 선행되어야 하는데, cmdi/pathtraver는 train n이 77~78로 작아 보정 계수 추정 자체가 불안정하다.
3. **캐스케이드가 held-out에서 이미 견고하게 재현됐다** — 기각 정확도 1.0000이 4개 카테고리 전부에서 유지됐고(146건 기각, 정탐 손실 0), F1도 train 대비 과적합 징후가 없다. 검증된 단순한 규칙을 두고 복잡도를 늘릴 근거가 부족하다.

정리하면 **비용(보정 파이프라인 + 우도비 추정 + 누수 관리) 대비 기대 이득이 낮다**는 판단이다. 리포트에는 "검토했고, 실측 근거를 바탕으로 착수하지 않기로 결정했다"로 기록한다 — 방법론 선택의 근거를 남기는 것 자체가 연구 산출물이다.

### CWE 데이터 커버리지 갭 — CWE-502, CWE-798 (2026-08-03 확인)

| CWE | OWASP Benchmark v1.2 | Juliet Test Suite(Java, NIST SARD) |
|---|---|---|
| CWE-502 (Insecure Deserialization) | ❌ 없음 (11개 카테고리 실측 확인: sqli/xss/cmdi/pathtraver/crypto/hash/weakrand/trustbound/securecookie/ldapi/xpathi) | ❌ 없음 (가장 가까운 `CWE499_Sensitive_Data_Serializable`은 다른 취약점) |
| CWE-798 (Use of Hard-coded Credentials) | ❌ 없음 (`trustbound`는 CWE-501이지 CWE-798이 아님 — 혼동 주의) | ⚠️ 정확히 일치하는 항목 없음. 근접 하위 항목 `CWE259_Hard_Coded_Password`만 존재(CWE-798의 좁은 하위 범주) |

두 데이터셋 모두 정량 벤치마크용 라벨링 테스트케이스가 없어서, 프로젝트 스코프 요약 문서에 명시된 6개 CWE 중 이 2개는 **현재 방법론(라벨링된 벤치마크 정량평가)으로 다루기 어려움**. 3단계(실제 오픈소스 PR/CVE 연동) 때 정성적 데모로 다루거나, 다른 CWE로 스코프를 조정하는 방안을 다음 논의에서 결정 필요.

### 다운로드/필터링/스캔 완료 카테고리 (2026-08-03 기준)

| 카테고리 | CWE | 데이터 필터링 | Semgrep 스캔·평가 | LLM 단독 | 하이브리드 |
|---|---|---|---|---|---|
| sqli | 89 | ✅ | ✅ | ✅ 실측 완료 | ✅ 실측 완료 |
| xss | 79 | ✅ | ✅ | ✅ 실측 완료 | ✅ 실측 완료 |
| cmdi | 78 | ✅ | ✅ | ✅ 실측 완료 | ✅ 실측 완료 |
| pathtraver | 22 | ✅ | ✅ | ✅ 실측 완료 | ✅ 실측 완료 |
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

**실제 GitHub 저장소 + ngrok + 진짜 PR로 엔드투엔드 검증 완료 (2026-08-03)**:
- ngrok 설치(winget) → authtoken 등록 → `ngrok http 8000` 터널링 → GitHub REST API로 웹훅 등록(repo: `SANGWOOK0416/ai-code-review-platform`), `GITHUB_WEBHOOK_SECRET` 발급해 서명 검증도 활성화한 채로 테스트
- `ping` 이벤트 200 OK 확인
- `test/webhook-pr-demo` 브랜치로 실제 PR #1 오픈(`opened` 이벤트) → 분석 완료, 요약 코멘트 자동 게시 확인. 단, 첫 커밋의 diff 범위 밖 라인이라 라인 코멘트 4건은 422로 실패 (README 트러블슈팅 표에 정리된 케이스와 일치 — 정상 동작)
- 같은 PR에 커밋 추가 푸시 → `synchronize` 이벤트 재트리거 확인, 이번엔 diff 범위 안이라 **라인 코멘트 4건 전부 성공 게시** (semgrep `tainted-sql-from-http-request`, `formatted-sql-string`, XSS `no-direct-response-writer` 룰 등 실제 탐지)
- → 파이프라인 전체("실제 GitHub PR → 웹훅 → 정적분석 → (mock)LLM → 하이브리드 통합 → PR 코멘트 게시")가 mock 페이로드가 아닌 실제 환경에서 동작함을 증명

**2026-10-18 갱신 — 아래 중 확인 완료된 것**:
- Docker 이미지 빌드: `docker build` 성공(semgrep 1.181.0, `python:3.11-slim` 베이스에서 정상 설치·동작). 컨테이너 내 `semgrep --version` 정상, `ANTHROPIC_API_KEY`를 값 노출 없이 주입해 기동 후 `GET /health` → `200 {"status":"ok","llm_mode":"real"}` 확인. `BenchmarkTest00024.java`를 컨테이너 안에서 직접 스캔해 CWE-89(`tainted-sql-from-http-request`) finding도 정상 탐지(웹훅 실 배포 경로의 캐스케이드 게이트가 실제로 열림을 증명)
- `.github/workflows/ci.yml`의 실제 GitHub Actions 실행 결과: **2026-08-05(`dd1dabb`)부터 2026-10-18 이전까지 전부 failure였음을 확인** — 원인과 수정은 9장 "CI의 Linux 실패 원인 조사·수정 완료" 참고. 수정 커밋(`f72ea29`) push 후 **Actions green 확인(2026-08-03 이후 첫 성공)**

**2026-10-18 추가 갱신 — 실제 PR E2E(실 API 모드) 검증 완료**: 새 `GITHUB_WEBHOOK_SECRET` 발급 + ngrok 재설정 후 PR #2(`test/webhook-e2e-real-api`)로 검증. 3개 케이스(취약/안전/Semgrep 미탐지) 전부 기대 티어와 일치, LLM 실 API 호출 2건(Semgrep 미탐지 케이스는 0건으로 캐스케이드 게이트 정상 확인). 상세는 9장 "웹훅 mock→실 API 전환" 항목 참고.

**남은 항목**:
- 웹훅 처리의 비동기화 — `/webhook` 핸들러가 Semgrep 스캔+LLM 호출을 동기로 전부 처리해 실측 ~41초가 걸림. GitHub의 웹훅 delivery 타임아웃(~10초)을 넘겨 Recent Deliveries에는 500(타임아웃)으로 기록되지만, 서버는 응답 후에도 처리를 이어가 코멘트 게시 자체는 정상 동작함. 운영 전환 전에는 즉시 200 ACK 후 백그라운드로 분석하는 구조로 바꿀 필요
