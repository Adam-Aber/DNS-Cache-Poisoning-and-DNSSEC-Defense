#!/usr/bin/env bash
# Fallback: force all outbound DNS to source port 33333 via iptables SNAT.
# Use only if Unbound's outgoing-port-permit directive does not actually
# pin the source port (verify with tcpdump per plan Task 6).
set -euo pipefail

iptables -t nat -F OUTPUT
iptables -t nat -A OUTPUT -p udp --dport 53 -j SNAT --to-source :33333

# Persist across reboots
export DEBIAN_FRONTEND=noninteractive
apt-get install -y iptables-persistent
netfilter-persistent save
echo "[+] iptables SNAT rule installed and persisted"
