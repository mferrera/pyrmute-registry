FROM ghcr.io/astral-sh/uv:python3.12-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY .git ./.git

RUN uv sync --frozen --no-install-project --no-dev --group server

COPY src ./src

RUN uv sync --frozen --no-dev --group server

# Final stage
FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

RUN useradd -m -u 1000 -s /bin/bash registry
USER registry

EXPOSE 8000

CMD ["pyrmute-registry", "serve"]
