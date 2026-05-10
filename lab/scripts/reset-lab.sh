#!/usr/bin/env bash
# Restart unbound on resolver and kill any lingering spoofer / tshark.
# Uses direct ssh via vagrant ssh-config (see _ssh-helper.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_ssh-helper.sh"
lab_ssh_init

echo "[*] Restarting unbound on resolver"
lab_ssh resolver "sudo systemctl restart unbound" \
  || { echo "resolver restart failed"; exit 1; }

echo "[*] Killing spoofer.py + tshark on attacker/resolver"
# Use process-name match (not -f). The string "spoofer" never appears in
# pkill's own argv, so the kill can't self-match. We kill any python3
# the spoofer might have spawned.
lab_ssh attacker "sudo pkill -x python3 2>/dev/null; true"
lab_ssh resolver "sudo pkill -x tshark 2>/dev/null; true"

echo "[*] Lab reset OK"
