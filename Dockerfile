# ---- Frontend build stage (Tailwind -> static/dist.css) ----
FROM node:22-slim AS frontend
WORKDIR /frontend
COPY package.json ./
RUN npm install --no-audit --no-fund
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

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

# Prefer the freshly built production CSS; fall back to repo-committed dist.css.
COPY --from=frontend /frontend/dist.css /app/app/static/css/dist.css

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
