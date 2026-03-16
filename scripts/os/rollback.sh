#!/usr/bin/env bash
set -euo pipefail

echo "[openclaw-os] rollback requested"

if command -v bootctl >/dev/null 2>&1; then
  echo "Detected systemd-boot tooling."
else
  echo "systemd-boot tooling not detected."
fi

cat <<'MSG'
OpenClaw OS rollback scaffold reached.
Implement slot-aware rollback here (A/B switch, snapshot revert, or bootloader entry rollback),
then keep this command idempotent and audit-logged.
MSG
