#!/usr/bin/env bash
set -euo pipefail

echo "[claos] developer quickstart"

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is required. Install pnpm first: npm install -g pnpm" >&2
  exit 1
fi

echo "[claos] installing dependencies..."
pnpm install

echo "[claos] building project..."
pnpm build

echo "[claos] enforcing OS security baseline..."
pnpm os:security:enforce

echo "[claos] checking strict status..."
pnpm os:security:status

cat <<'MSG'

CLAOS developer quickstart complete.

Useful next commands:
  pnpm test
  pnpm openclaw os app create "My First App" --type simple
  pnpm openclaw os app list

MSG
