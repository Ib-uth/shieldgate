#!/usr/bin/env bash
# Run the same integration flow as .github/workflows ci.yml (integration-test job).
# Prerequisites: Postgres and Redis reachable (e.g. docker compose or local services).
#
# Usage (from repo root):
#   ./scripts/run-integration-ci-locally.sh
#
# Optional: DATABASE_URL, REDIS_URL, etc. override defaults below.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt
python -m pip install -q pytest httpx redis

mkdir -p keys models
if [[ ! -f keys/private.pem ]]; then
  python scripts/generate_keys.py --private-key keys/private.pem --public-key keys/public.pem
fi
if [[ ! -f models/threat_model.joblib ]]; then
  python scripts/train_model.py --output models/threat_model.joblib --samples 1000
fi

export PYTHONPATH=apps
export NO_PROXY=127.0.0.1,localhost
export DATABASE_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/test_shieldgate}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
export JWT_PRIVATE_KEY_PATH="${JWT_PRIVATE_KEY_PATH:-keys/private.pem}"
export JWT_PUBLIC_KEY_PATH="${JWT_PUBLIC_KEY_PATH:-keys/public.pem}"
export THREAT_MODEL_PATH="${THREAT_MODEL_PATH:-models/threat_model.joblib}"
export THREAT_SCORE_BLOCK_THRESHOLD="${THREAT_SCORE_BLOCK_THRESHOLD:-2.0}"
export THREAT_SCORE_FLAG_THRESHOLD="${THREAT_SCORE_FLAG_THRESHOLD:-2.0}"
export DOWNSTREAM_URL="${DOWNSTREAM_URL:-http://127.0.0.1:8001}"
export DOWNSTREAM_API_PREFIX="${DOWNSTREAM_API_PREFIX:-api/v1}"

python -m uvicorn mock_service.main:app --host 0.0.0.0 --port 8001 &
PIDS+=($!)

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8001/health" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf "http://127.0.0.1:8001/health" || {
  echo "mock service failed to become ready"
  exit 1
}

python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000 &
PIDS+=($!)

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8000/health/" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf "http://127.0.0.1:8000/health/" || {
  echo "gateway failed to become ready"
  exit 1
}

pytest tests/integration/ -v --no-cov
