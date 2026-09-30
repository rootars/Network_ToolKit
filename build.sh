#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python3}"

if [[ -d "venv" ]]; then
  source "venv/bin/activate"
  PYTHON="python"
fi

echo "[*] Bağımlılıklar kuruluyor..."
"$PYTHON" -m pip install -q --upgrade pip
"$PYTHON" -m pip install -q -r requirements-build.txt

OS_NAME="$(uname -s)"
case "$OS_NAME" in
  Darwin) BINARY_NAME="rootipv6-netaudit-macos" ;;
  Linux)  BINARY_NAME="rootipv6-netaudit-linux" ;;
  *)      BINARY_NAME="rootipv6-netaudit" ;;
esac

mkdir -p dist

echo "[*] Nuitka build başlatılıyor (${BINARY_NAME})..."
"$PYTHON" -m nuitka \
  --onefile \
  --follow-imports \
  --enable-plugin=multiprocessing \
  --output-dir=dist \
  --output-filename="${BINARY_NAME}" \
  --remove-output \
  --lto=yes \
  --python-flag=-O \
  --assume-yes-for-downloads \
  --include-package=modules \
  --include-package=colorama \
  --include-package-data=colorama \
  --include-package=dns \
  --include-package=pysnmp \
  --include-package=pyasn1 \
  --include-package=netaddr \
  --include-package-data=netaddr \
  main.py

echo "[+] Build tamamlandı: dist/${BINARY_NAME}"
