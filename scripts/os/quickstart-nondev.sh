#!/usr/bin/env bash
set -euo pipefail

echo "[claos] non-dev quickstart"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required. Install Node.js 22+ first." >&2
  exit 1
fi

echo "[claos] installing CLI package..."
npm install -g openclaw@latest

echo "[claos] enforcing OS security baseline..."
claos os security enforce

echo "[claos] checking strict status..."
claos os security status

cat <<'MSG'

CLAOS quickstart complete.

Next:
  1) Optional local model:
       ollama pull qwen3:4b
  2) Create your first local app:
       claos os app create "My First App" --type simple
  3) View app list:
       claos os app list

MSG
