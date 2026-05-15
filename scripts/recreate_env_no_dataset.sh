#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PY_VER="${PY_VER:-3.7.17}"
VENV_DIR="${VENV_DIR:-.venv37_clean}"

LIBFFI_VER="${LIBFFI_VER:-3.4.6}"
LIBFFI_PREFIX="${LIBFFI_PREFIX:-$HOME/.local/opt/libffi-$LIBFFI_VER}"

BZIP2_VER="${BZIP2_VER:-1.0.8}"
BZIP2_PREFIX="${BZIP2_PREFIX:-$HOME/.local/opt/bzip2-$BZIP2_VER}"

UPX_VER="${UPX_VER:-5.0.2}"
UPX_URL="${UPX_URL:-https://github.com/upx/upx/releases/download/v${UPX_VER}/upx-${UPX_VER}-amd64_linux.tar.xz}"

EMBER_MODEL_URL="${EMBER_MODEL_URL:-https://raw.githubusercontent.com/Azure/2020-machine-learning-security-evasion-competition/master/defender/defender/models/ember_model.txt.gz}"
EMBER_MODEL_PATH="malware_rl/envs/utils/ember_model.txt"
LGB_EMBER_MODEL_PATH="malware_rl/envs/utils/lgb_ember_model.txt"
UPX_TARGET_PATH="malware_rl/envs/controls/upx"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar
need_cmd make
need_cmd gcc
need_cmd pyenv

mkdir -p "$HOME/.local/src" "$HOME/.local/opt"

build_libffi() {
  if [[ -d "$LIBFFI_PREFIX" ]]; then
    return 0
  fi

  local srcdir="$HOME/.local/src/libffi-$LIBFFI_VER"
  local tarball="$HOME/.local/src/libffi-$LIBFFI_VER.tar.gz"
  local url="https://github.com/libffi/libffi/releases/download/v${LIBFFI_VER}/libffi-${LIBFFI_VER}.tar.gz"

  echo "Building libffi into $LIBFFI_PREFIX"
  [[ -f "$tarball" ]] || curl -L -o "$tarball" "$url"
  rm -rf "$srcdir"
  tar -xzf "$tarball" -C "$HOME/.local/src"
  cd "$srcdir"
  ./configure --prefix="$LIBFFI_PREFIX"
  make -j"$(nproc 2>/dev/null || echo 2)"
  make install
  cd "$ROOT_DIR"
}

build_bzip2() {
  if [[ -d "$BZIP2_PREFIX" ]]; then
    return 0
  fi

  local srcdir="$HOME/.local/src/bzip2-$BZIP2_VER"
  local tarball="$HOME/.local/src/bzip2-$BZIP2_VER.tar.gz"
  local url="https://sourceware.org/pub/bzip2/bzip2-${BZIP2_VER}.tar.gz"

  echo "Building bzip2 into $BZIP2_PREFIX"
  [[ -f "$tarball" ]] || curl -L -o "$tarball" "$url"
  rm -rf "$srcdir"
  tar -xzf "$tarball" -C "$HOME/.local/src"
  cd "$srcdir"
  make clean || true
  make -f Makefile-libbz2_so
  make -j"$(nproc 2>/dev/null || echo 2)"
  make PREFIX="$BZIP2_PREFIX" install

  # Ensure shared library exists in prefix (Python build probes linkable libs).
  if [[ -f "$srcdir/libbz2.so.1.0.${BZIP2_VER}" ]]; then
    mkdir -p "$BZIP2_PREFIX/lib"
    cp "$srcdir/libbz2.so.1.0.${BZIP2_VER}" "$BZIP2_PREFIX/lib/"
    ln -sf "libbz2.so.1.0.${BZIP2_VER}" "$BZIP2_PREFIX/lib/libbz2.so.1.0"
    ln -sf "libbz2.so.1.0.${BZIP2_VER}" "$BZIP2_PREFIX/lib/libbz2.so"
  fi

  cd "$ROOT_DIR"
}

install_pyenv_python() {
  echo "Installing Python $PY_VER via pyenv (with local libffi+bzip2)"
  export CPPFLAGS="-I${LIBFFI_PREFIX}/include -I${BZIP2_PREFIX}/include"
  export CFLAGS="$CPPFLAGS"
  export LDFLAGS="-L${LIBFFI_PREFIX}/lib -L${BZIP2_PREFIX}/lib -Wl,-rpath,${LIBFFI_PREFIX}/lib -Wl,-rpath,${BZIP2_PREFIX}/lib"
  export LIBS="-lbz2"
  export PKG_CONFIG_PATH="${LIBFFI_PREFIX}/lib/pkgconfig"
  pyenv install -f "$PY_VER"
}

create_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating venv at $VENV_DIR"
    python3.7 -m venv "$VENV_DIR"
  fi

  "$VENV_DIR/bin/pip" install --upgrade pip 'setuptools<66' wheel==0.37.1
}

install_python_deps() {
  echo "Installing pip dependencies from requirements.txt"
  "$VENV_DIR/bin/pip" install -r requirements.txt
}

download_ember_model() {
  if [[ ! -f "$EMBER_MODEL_PATH" ]]; then
    echo "Downloading Ember model to $EMBER_MODEL_PATH"
    curl -L "$EMBER_MODEL_URL" -o /tmp/ember_model.txt.gz
    gunzip -c /tmp/ember_model.txt.gz > "$EMBER_MODEL_PATH"
  fi

  if [[ ! -f "$LGB_EMBER_MODEL_PATH" ]]; then
    cp "$EMBER_MODEL_PATH" "$LGB_EMBER_MODEL_PATH"
  fi
}

download_upx() {
  if [[ -x "$UPX_TARGET_PATH" ]]; then
    return 0
  fi

  echo "Downloading UPX to $UPX_TARGET_PATH"
  curl -L "$UPX_URL" -o /tmp/upx.tar.xz
  rm -rf /tmp/upx-extract
  mkdir -p /tmp/upx-extract
  tar -xf /tmp/upx.tar.xz -C /tmp/upx-extract
  local upx_bin
  upx_bin="$(find /tmp/upx-extract -type f -name upx -perm -u+x 2>/dev/null | head -n 1)"
  if [[ -z "$upx_bin" ]]; then
    echo "Could not find extracted upx binary" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$UPX_TARGET_PATH")"
  cp "$upx_bin" "$UPX_TARGET_PATH"
  chmod +x "$UPX_TARGET_PATH"
}

download_benign_strings() {
  if [[ -f "malware_rl/envs/controls/trusted/xournalpp-1.0.18-windows.exe" ]] && [[ -f "malware_rl/envs/controls/good_strings/xournal-strings.txt" ]]; then
    return 0
  fi

  echo "Downloading benign trusted file + strings output (no malware samples)"
  "$VENV_DIR/bin/python" download_deps.py --strings
}

build_libffi
build_bzip2
install_pyenv_python
create_venv
install_python_deps
download_ember_model
download_upx
download_benign_strings

echo "Done."
echo "Activate with: source $VENV_DIR/bin/activate"
