#!/usr/bin/env bash
# Renders deploy/prometheus.yml (which contains ${METRICS_API_KEY}) via envsubst.
# Plain `docker -v prometheus.yml` does no interpolation and would scrape with
# the literal string "${METRICS_API_KEY}" -> /metrics 401.
set -euo pipefail
if [[ -z "${METRICS_API_KEY:-}" ]]; then
  echo "ERROR: METRICS_API_KEY must be set to render prometheus.yml" >&2
  exit 1
fi
if [[ "${METRICS_API_KEY}" == *"CHANGE_ME"* ]]; then
  echo "ERROR: METRICS_API_KEY still contains CHANGE_ME placeholder" >&2
  exit 1
fi
out="${1:-/tmp/prometheus.rendered.yml}"
envsubst < deploy/prometheus.yml > "$out"
echo "Rendered $out"
