#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0"
VERSION_FULL="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

error() {
  echo -e "${RED}[!] HATA:${NC} $1" >&2
  exit 1
}

info() {
  echo -e "${CYAN}[*]${NC} $1"
}

success() {
  echo -e "${GREEN}[+]${NC} $1"
}

OS_NAME="$(uname -s)"
case "$OS_NAME" in
  Darwin)
    PLATFORM="macos"
    BINARY_NAME="rootipv6-netaudit-macos"
    ;;
  Linux)
    PLATFORM="linux"
    BINARY_NAME="rootipv6-netaudit-linux"
    ;;
  *)
    error "Bu script yalnızca Linux veya macOS üzerinde çalışır. Algılanan: ${OS_NAME}"
    ;;
esac

ZIP_NAME="rootipv6-netaudit-${PLATFORM}-v${VERSION}.zip"
PYTHON="${PYTHON:-python3}"

if [[ -d "venv" ]]; then
  source "venv/bin/activate"
  PYTHON="python"
fi

command -v "$PYTHON" >/dev/null 2>&1 || error "Python bulunamadı. python3 veya venv kurun."
command -v zip >/dev/null 2>&1 || error "'zip' komutu bulunamadı. (macOS: zip varsayılan, Linux: apt install zip)"

for file in README.md LICENSE CHANGELOG.md main.py; do
  [[ -f "$file" ]] || error "Gerekli dosya eksik: ${file}"
done

info "ROOTIPV6 NetAudit Toolkit — Release Build v${VERSION_FULL}"
info "Platform: ${PLATFORM} (${OS_NAME})"
info "Binary adı: ${BINARY_NAME}"
echo ""

info "Bağımlılıklar kuruluyor..."
"$PYTHON" -m pip install -q --upgrade pip || error "pip güncellenemedi."
"$PYTHON" -m pip install -q -r requirements-build.txt || error "Build bağımlılıkları kurulamadı."

mkdir -p dist release

info "Nuitka build başlatılıyor (bu işlem birkaç dakika sürebilir)..."
if ! "$PYTHON" -m nuitka \
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
  main.py; then
  error "Nuitka build başarısız. C derleyicisi (gcc/clang) kurulu olduğundan emin olun."
fi

DIST_BINARY="dist/${BINARY_NAME}"
[[ -f "$DIST_BINARY" ]] || error "Binary oluşturulamadı: ${DIST_BINARY}"

cp "$DIST_BINARY" "release/${BINARY_NAME}"
chmod +x "release/${BINARY_NAME}"
success "Binary kopyalandı: release/${BINARY_NAME}"

STAGING="release/_staging-${PLATFORM}"
rm -rf "$STAGING"
mkdir -p "$STAGING"

cp "$DIST_BINARY" "${STAGING}/${BINARY_NAME}"
chmod +x "${STAGING}/${BINARY_NAME}"
cp README.md LICENSE CHANGELOG.md "$STAGING/"

info "ZIP paketi oluşturuluyor: release/${ZIP_NAME}"
rm -f "release/${ZIP_NAME}"
(
  cd "$STAGING"
  zip -rq "../${ZIP_NAME}" .
)

rm -rf "$STAGING"

echo ""
success "Release paketi hazır!"
echo -e "  ${YELLOW}Binary:${NC}  release/${BINARY_NAME}"
echo -e "  ${YELLOW}ZIP:${NC}     release/${ZIP_NAME}"
echo ""
echo -e "${CYAN}GitHub Releases için:${NC} release/${ZIP_NAME} dosyasını yükleyin."
echo -e "  Etiket önerisi: v${VERSION_FULL}"
