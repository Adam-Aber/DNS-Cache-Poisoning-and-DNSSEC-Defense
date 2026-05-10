#!/usr/bin/env bash
# Print the host-only adapter name on the current VM.
# Used by run-part1.sh so tshark works regardless of NIC naming.
ip -o -4 addr show \
  | awk '$4 ~ /^192\.168\.56\./ {print $2; exit}'
