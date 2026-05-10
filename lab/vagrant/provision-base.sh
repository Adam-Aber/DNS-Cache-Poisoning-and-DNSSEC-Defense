#!/usr/bin/env bash
# Common provisioning for all three VMs.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y curl tcpdump tshark net-tools dnsutils iptables

# Allow non-root tshark capture
groupadd -f wireshark
usermod -aG wireshark vagrant
chgrp wireshark /usr/bin/dumpcap
chmod 4750 /usr/bin/dumpcap
