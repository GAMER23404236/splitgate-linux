#!/usr/bin/env bash
# SplitGate - uninstaller.  Usage: ./uninstall.sh [--purge]
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E bash "$0" "$@"
fi

systemctl disable --now dpigec.service 2>/dev/null || true
nft delete table inet dpigec 2>/dev/null || true   # a leftover redirect rule must not cut your internet
make uninstall PREFIX=/usr PURGE="$PURGE"
systemctl daemon-reload 2>/dev/null || true
echo "✔ SplitGate removed."
