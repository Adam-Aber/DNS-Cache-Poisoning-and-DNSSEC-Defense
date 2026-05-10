#!/usr/bin/env bash
# End-to-end Part 1 demo. Run on the host.
#
#   ./run-part1.sh             # default: capture pcap, attempt poison, prove
#
# Captures docs/captures/poison.pcap. Returns 0 on SUCCESS.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_ssh-helper.sh"
lab_ssh_init

PCAP_OUT="$HERE/../../docs/captures/poison.pcap"
mkdir -p "$(dirname "$PCAP_OUT")"

echo "[1/5] Reset lab"
"$HERE/reset-lab.sh"

echo "[2/5] Start tshark on resolver (background)"
lab_ssh resolver "
  IF=\$(/lab/scripts/discover-iface.sh)
  sudo nohup tshark -i \$IF -w /tmp/poison.pcap \
       -f 'port 53 or host 192.168.56.10' \
       >/tmp/tshark.log 2>&1 &
  echo \$! | sudo tee /tmp/tshark.pid >/dev/null
  sleep 1
"

echo "[3/5] Run spoofer on attacker (foreground, up to 60s)"
set +e
lab_ssh attacker "sudo python3 /lab/attacker/spoofer.py"
SPOOFER_RC=$?
set -e

echo "[4/5] Run demo.sh on victim"
set +e
lab_ssh victim "/lab/victim/demo.sh"
VICTIM_RC=$?
set -e

echo "[5/5] Stop tshark and copy pcap"
lab_ssh resolver "
  sudo kill \$(cat /tmp/tshark.pid) 2>/dev/null || true
  sleep 1
  sudo chmod 0644 /tmp/poison.pcap
"
scp -F "$LAB_SSH_CONFIG" -o LogLevel=ERROR resolver:/tmp/poison.pcap "$PCAP_OUT"

if (( SPOOFER_RC == 0 && VICTIM_RC == 0 )); then
  echo "[+] Part 1 demo SUCCESS  (pcap → $PCAP_OUT)"
  exit 0
fi
echo "[-] Part 1 demo FAILED  (spoofer=$SPOOFER_RC victim=$VICTIM_RC)"
exit 1
