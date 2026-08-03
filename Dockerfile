# syntax=docker/dockerfile:1

# ---- Stage 1: 빌드 (의존성 설치만 담당, 최종 이미지에는 포함되지 않음) ----
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .

# --prefix=/install 로 격리 설치 → 최종 스테이지에는 이 결과물만 복사
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Stage 2: 런타임 (최소 이미지) ----
FROM python:3.11-slim

# semgrep은 musl libc(alpine) 기반에서 정상 동작하지 않으므로 glibc 기반(debian-slim) 유지 필수
COPY --from=builder /install /usr/local

WORKDIR /app
COPY app/ ./app/
COPY scripts/ ./scripts/

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
