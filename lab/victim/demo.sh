#!/usr/bin/env bash
# Non-interactive proof of redirection.
# Run AFTER spoofer.py reports success on the attacker.
# Exit 0 if poisoned, non-zero otherwise.
set -uo pipefail

RESOLVER="${RESOLVER:-192.168.56.20}"
TARGET="${TARGET:-www.target.lab}"
EXPECT="${EXPECT:-192.168.56.10}"
LOGDIR="${LOGDIR:-/lab/victim/logs}"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/run-$(date +%Y%m%d-%H%M%S).log"

{
  echo "=== Phase 1 — Post-attack dig ==="
  dig "@$RESOLVER" "$TARGET" +short
  echo
  echo "=== Phase 2 — HTTP fetch ==="
  # The poisoned resolver only has the A record; AAAA still goes to the
  # black-hole forwarder and stalls glibc's getaddrinfo for ~10 s. To
  # demonstrate the redirect cleanly, resolve once via dig (cache hit
  # → instant) and pin curl with --resolve, which bypasses getaddrinfo.
  POISONED_IP=$(dig "@$RESOLVER" "$TARGET" +short | head -n1)
  echo "(curl --resolve $TARGET:80:$POISONED_IP)"
  curl -4 -sS -m 5 --resolve "$TARGET:80:$POISONED_IP" \
       "http://$TARGET/" | head -n 8
} | tee "$LOG"

ANSWER=$(dig "@$RESOLVER" "$TARGET" +short)
if [[ "$ANSWER" == "$EXPECT" ]]; then
  echo "[+] PASS — $TARGET resolves to $EXPECT (poisoned)"
  exit 0
fi
echo "[-] FAIL — got '$ANSWER', expected '$EXPECT'"
exit 2
