#!/usr/bin/env bash
# Resolver provisioner — installs Unbound with the weakened config.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y unbound

# Allow loose reverse-path filtering so spoofed-source packets are accepted.
# Without this, the resolver kernel drops UDP packets whose source IP
# (192.168.56.99) does not match the reverse routing table.
cat > /etc/sysctl.d/99-lab.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl --system >/dev/null

# systemd-resolved must not own :53
systemctl disable --now systemd-resolved || true
rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' > /etc/resolv.conf

# Drop our config and disable any stock forwarders include
install -o root -g root -m 0644 \
  /lab/resolver/unbound-vulnerable.conf \
  /etc/unbound/unbound.conf.d/lab.conf
sed -i 's|^include:|#include:|' /etc/unbound/unbound.conf || true

mkdir -p /var/log/unbound
chown unbound:unbound /var/log/unbound

# Static neighbor for the unassigned forwarder IP so ARP doesn't drop the
# resolver's outbound query. The MAC is intentionally fake — packets to
# .99 disappear into the black hole, which is exactly what we want.
ip neigh replace 192.168.56.99 lladdr 02:00:00:00:00:99 dev enp0s8 nud permanent || true
cat > /etc/networkd-dispatcher/routable.d/50-static-neigh.sh <<'EOF'
#!/bin/sh
ip neigh replace 192.168.56.99 lladdr 02:00:00:00:00:99 dev enp0s8 nud permanent
EOF
chmod +x /etc/networkd-dispatcher/routable.d/50-static-neigh.sh

# Validate before starting — fail provisioner loudly if config is broken
unbound-checkconf
systemctl enable --now unbound
systemctl status unbound --no-pager | head -n 5
