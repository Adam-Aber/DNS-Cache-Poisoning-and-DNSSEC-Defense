#!/usr/bin/env bash
# Victim provisioner — pin /etc/resolv.conf to the lab resolver.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y dnsutils curl

# Disable systemd-resolved so /etc/resolv.conf can be static
systemctl disable --now systemd-resolved || true
rm -f /etc/resolv.conf
echo 'nameserver 192.168.56.20' > /etc/resolv.conf
chattr +i /etc/resolv.conf
