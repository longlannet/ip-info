#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[ip-info] no installation needed"
echo "[ip-info] python: $(command -v python3)"
python3 --version
echo "[ip-info] install complete"
