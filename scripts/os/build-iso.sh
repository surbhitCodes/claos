#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="${OPENCLAW_OS_OUTPUT_DIR:-$ROOT_DIR/.artifacts/openclaw-os}"
UBUNTU_RELEASE="${OPENCLAW_OS_UBUNTU_RELEASE:-noble}"
WORK_DIR="${OPENCLAW_OS_WORK_DIR:-$OUTPUT_DIR/work}"

mkdir -p "$OUTPUT_DIR" "$WORK_DIR"

echo "[openclaw-os] build prototype"
echo "  root:    $ROOT_DIR"
echo "  output:  $OUTPUT_DIR"
echo "  release: $UBUNTU_RELEASE"

echo "[openclaw-os] checking build dependencies..."
missing=0
for tool in debootstrap xorriso mksquashfs grub-mkstandalone; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "  missing: $tool"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  cat <<'MSG'
Missing one or more ISO build dependencies.
Install the required tooling, then rerun this script.

Recommended Ubuntu packages:
  sudo apt-get update
  sudo apt-get install -y debootstrap xorriso squashfs-tools grub-pc-bin grub-efi-amd64-bin
MSG
  exit 1
fi

cat <<MSG
This script is the OpenClaw OS build entrypoint scaffold.
Next implementation step is wiring a full rootfs + installer pipeline
(debootstrap/live-build/autoinstall assets) under scripts/os/.

For now, it verifies prerequisites and reserves artifact paths:
  $OUTPUT_DIR
  $WORK_DIR
MSG
