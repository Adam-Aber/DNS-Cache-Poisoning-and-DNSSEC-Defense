#!/usr/bin/env bash
# Attacker provisioner — Python+Scapy spoofer + Nginx PWNED page.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# --- Spoofer runtime ---
apt-get install -y python3 python3-pip python3-venv
pip3 install scapy==2.5.0

# --- Nginx PWNED page ---
apt-get install -y nginx
mkdir -p /var/www/pwned
install -o root -g root -m 0644 \
  /lab/attacker/nginx/index.html /var/www/pwned/index.html
install -o root -g root -m 0644 \
  /lab/attacker/nginx/pwned.conf /etc/nginx/sites-available/pwned
ln -sf /etc/nginx/sites-available/pwned /etc/nginx/sites-enabled/pwned
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
