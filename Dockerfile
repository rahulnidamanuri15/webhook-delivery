# ---- Frontend build stage (Tailwind -> static/dist.css) ----
FROM node:22-slim AS frontend
WORKDIR /frontend
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY app/static/css/input.css ./app/static/css/input.css
COPY app/templates ./app/templates
# Build production CSS; output is copied into the final image.
RUN npx tailwindcss -i ./app/static/css/input.css -o ./dist.css --minify

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir --no-deps . \
    && apt-get purge -y --auto-remove build-essential 2>/dev/null || true

COPY app ./app
COPY migrations ./migrations
COPY scripts ./scripts
COPY alembic.ini ./alembic.ini
COPY demo_receiver ./demo_receiver

# Prefer the freshly built production CSS; fall back to repo-committed dist.css.
COPY --from=frontend /frontend/dist.css /app/app/static/css/dist.css

# Run as non-root; fix ownership for runtime writes (SQLite fallback / logs)
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/live || exit 1


CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
