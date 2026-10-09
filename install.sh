#!/usr/bin/env bash
# SplitGate - installer for all Linux distributions (Arch/CachyOS, Debian/Ubuntu, Fedora, openSUSE)
#
# Usage:  ./install.sh [--no-deps] [--enable] [--now]
#   --no-deps  do not install dependencies
#   --enable   start automatically at boot
#   --now      start the service right after installing
set -euo pipefail


DEPS=1; ENABLE=0; NOW=0
for arg in "$@"; do
  case "$arg" in
    --no-deps) DEPS=0 ;;
    --enable)  ENABLE=1 ;;
    --now)     NOW=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$(readlink -f "$0")")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Administrator privileges are required; restarting with sudo..."
  exec sudo -E bash "$0" "$@"
fi

install_deps() {
  if command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm python nftables polkit python-pyqt6 make
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 nftables policykit-1 python3-pyqt6 make
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 nftables polkit python3-pyqt6 make
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3 nftables polkit python3-qt6 make
  else
    echo "Package manager not recognized. Install manually: python3, nftables, polkit, PyQt6, make" >&2
  fi
}

[ "$DEPS" -eq 1 ] && install_deps

for bin in python3 nft make; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Missing dependency: $bin" >&2; exit 1; }
done
python3 - <<'PY' || echo "WARNING: PyQt6 not found; the GUI will not work, the command line (dpigec) will."
import PyQt6.QtWidgets  # noqa
PY

make install PREFIX=/usr
systemctl daemon-reload 2>/dev/null || true

if [ "$ENABLE" -eq 1 ]; then systemctl enable dpigec.service; fi
if [ "$NOW" -eq 1 ];    then systemctl restart dpigec.service; fi

cat <<'MSG'

✔ SplitGate installed.

  GUI          : "SplitGate" in the application menu, or  dpigec-gui  in a terminal
  Command line : dpigec status | start | stop | probe   (dpigec --help)
  Service      : systemctl start|stop|enable dpigec

  First step: in the GUI, open the Test tab and press "Try strategies" to find
  the one that works on your network, then press Start.
MSG
