# DNS Cache Poisoning Lab — Part 1 Design

**Status:** Draft (for review)
**Date:** 2026-05-05
**Deadline (team-set):** 2026-05-08
**Course deadline:** 2026-05-12
**Scope:** Part 1 only (Tasks 1–5 of the project brief).

## 1. Overview

Build a self-contained virtual lab that demonstrates a DNS cache poisoning
attack against a deliberately-weakened recursive resolver. A victim machine
queries a fake domain (`www.target.lab`); the attacker forges a DNS reply,
injects an A record into the resolver's cache, and the victim's subsequent
HTTP request lands on the attacker's web server.

The lab is the foundation for Parts 2 (traffic analysis) and 3 (DNSSEC
defense), which reuse the same VMs.

### 1.1 Goals

1. Working attack reproducible from `vagrant up` in under 10 minutes.
2. Resolver weakening choices each map to a real-world hardening directive,
   so the report can compare vulnerable vs. hardened configurations.
3. Artifacts (pcap, screenshots, logs) sufficient to satisfy the project's
   "Working attack demonstration" and "Traffic analysis" deliverables.

### 1.2 Non-goals

- Kaminsky-style NS+glue zone-wide poisoning (deferred; single-record only).
- Real Internet domains. The lab is fully isolated on a host-only network.
- Attacks against modern hardened resolvers without weakening — out of scope
  for a 3-day build window.

## 2. Lab topology

Three Ubuntu 22.04 Server VMs in VirtualBox on a host-only network
`192.168.56.0/24`. No NAT — the lab cannot accidentally emit spoofed
traffic to the Internet.

| VM | Hostname  | IP              | RAM   | Role                                                                 |
|----|-----------|-----------------|-------|----------------------------------------------------------------------|
| 1  | attacker  | 192.168.56.10   | 2 GB  | Runs `spoofer.py` (Scapy) and Nginx serving the "PWNED" page on :80. |
| 2  | resolver  | 192.168.56.20   | 2 GB  | Runs Unbound (deliberately weakened). Listens on :53.                |
| 3  | victim    | 192.168.56.30   | 2 GB  | `/etc/resolv.conf` pinned to 192.168.56.20. Runs `dig`, `curl`.      |

Provisioned via a single `Vagrantfile` so the team can reproduce with one
command. Disk usage ~10 GB per VM.

### 2.1 Why host-only

- Allows SSH from the Windows host into each VM for editing and log capture.
- Isolates from the Internet: no risk of spoofing real DNS traffic.
- Allows screen recording of the demo from the host while VMs run headless.

## 3. Resolver configuration (deliberately weakened)

Unbound is the upstream choice (shorter config than BIND, easier to explain
in the report). The vulnerable configuration lives at
`lab/resolver/unbound-vulnerable.conf` and is dropped into
`/etc/unbound/unbound.conf.d/lab.conf` during provisioning.
`systemd-resolved` must be disabled so Unbound can bind :53.

```yaml
server:
  interface: 192.168.56.20
  access-control: 192.168.56.0/24 allow      # task 2: allow victim queries
  do-not-query-localhost: no
  use-caps-for-id: no                        # disable 0x20 case randomization
  outgoing-range: 1                          # one outbound socket
  outgoing-port-avoid: "0-65535"             # avoid all ports...
  outgoing-port-permit: "33333"              # ...except this one (pinned source port)
  harden-glue: no
  harden-referral-path: no
  qname-minimisation: no
  cache-min-ttl: 60                          # positive answers cached ≥60 s
  cache-max-ttl: 86400
  module-config: "iterator"                  # no validator loaded (Part 3 re-enables)

forward-zone:                                # send target.lab queries to a black hole
  name: "target.lab."
  forward-addr: 192.168.56.99                # unassigned IP, queries time out
```

> **Source-port pinning is brittle in Unbound.** The directives above are
> the documented way, but Unbound versions vary in how strictly they honor
> them. **Verify with `unbound-checkconf` and a tcpdump on the resolver
> VM as the first step of Day 1**, before anything else. If the source
> port still randomizes, fall back to an iptables SNAT rule on the
> resolver:
>
> ```
> iptables -t nat -A OUTPUT -p udp --dport 53 \
>          -j SNAT --to-source :33333
> ```
>
> The iptables fallback is more reliable and arguably easier to explain in
> the report ("we externally pinned the source port to simulate a
> resolver without RFC 5452"). The spec treats either approach as valid.
>
> `val-permissive-mode` was removed from the original draft — it has no
> effect when `module-config` doesn't load the validator, and including
> both was contradictory.

### 3.1 Why each knob matters (report table)

| Directive                          | Effect                                                          | Real-world defense it disables   |
|------------------------------------|-----------------------------------------------------------------|----------------------------------|
| `outgoing-port-permit: 33333`      | Collapses 16-bit source-port entropy to 1                       | RFC 5452 source port randomization |
| `use-caps-for-id: no`              | No 0x20 mixed-case echo                                         | DNS-0x20 query encoding          |
| `harden-glue: no`                  | Accepts unsolicited glue (sets up Kaminsky upgrade path)        | Bailiwick checking on glue       |
| `qname-minimisation: no`           | Full QNAME sent upstream                                        | RFC 9156 qname minimisation      |
| `module-config: "iterator"`        | DNSSEC validator not loaded (Part 3 swaps in `validator iterator`) | DNSSEC validation             |
| `forward-zone → 192.168.56.99`     | Legitimate response never arrives within forwarder timeout      | n/a — lab simplification         |

### 3.2 Verification (pre-attack baseline)

From the victim, before any attack runs:

```
$ dig @192.168.56.20 www.target.lab +short
;; communications error to 192.168.56.99#53: timed out
;; communications error to 192.168.56.99#53: timed out
;; communications error to 192.168.56.99#53: timed out
```

Result: SERVFAIL after ~5 s. This screenshot becomes
`docs/screenshots/02-resolver-baseline.png`.

A general-purpose query (`dig @192.168.56.20 example.com`) must still
resolve normally — only `target.lab` goes to the black hole. This is
important for report realism: the resolver is "live", just exploitable.

## 4. Attacker components

### 4.1 `spoofer.py` (Python 3 + Scapy)

Single file, ~80 lines, two threads.

**Thread 1 — Trigger.** Sends one A-query for `www.target.lab` to
`192.168.56.20:53` every ~6 s (slightly longer than Unbound's negative
cache TTL, default 5 s). Unbound deduplicates in-flight queries with the
same qname/qtype, so firing the trigger faster does *not* open additional
race windows — only one outbound query is in flight at a time. The 6-second
cadence ensures each trigger reliably produces a fresh outbound query to
`192.168.56.99` after the previous SERVFAIL has expired from the negative
cache.

**Thread 2 — Spoof flood.** Crafts forged UDP/DNS responses targeting the
resolver. Each packet:

- IP src = `192.168.56.99` (impersonating the forwarder)
- IP dst = `192.168.56.20`
- UDP sport = 53, dport = 33333 (the resolver's fixed source port)
- DNS `qr=1, aa=1, qd=www.target.lab A,
       an=A 192.168.56.10 TTL=86400`
- DNS transaction id = brute-force sweep over 0..65535

With port entropy collapsed to 1, sweeping all 65,536 txids takes well
under a second on the host-only network. The resolver accepts the first
spoofed reply that matches (dst IP, dst port, txid, question section)
during the forwarder timeout window (~5 s before SERVFAIL is returned to
the victim).

**Why two threads.** Even with one outbound query in flight at a time, the
flood thread must run continuously: the spoof must arrive *during* the
~5-second forwarder-timeout window. If a sweep finishes before a trigger
fires, the spoof packets are dropped (no matching pending query). Running
both threads concurrently keeps spoofs landing during every active window.

**CLI:**

```
sudo python3 spoofer.py \
    --resolver 192.168.56.20 \
    --target www.target.lab \
    --spoof-ip 192.168.56.10 \
    --src-port 33333
```

`spoofer.py` exits with `[+] poisoned in N attempts (T seconds)` after
re-querying the resolver and seeing the malicious A record cached.

**Repeatable demo runs.** `lab/scripts/reset-lab.sh` runs
`systemctl restart unbound` on the resolver via SSH to flush the cache
between runs. (Simpler than wiring up `unbound-control` keys.)

### 4.2 Malicious web server

Nginx on the attacker VM, port 80, serving a single static `index.html`:

```html
<h1>YOU'VE BEEN PWNED</h1>
<p>This page was served from 192.168.56.10 because the DNS cache for
   www.target.lab was poisoned. A real attacker would serve a phishing
   clone of the bank you thought you were visiting.</p>
```

Deliberately ugly so it screenshots unmistakably for the demo video.

### 4.3 Repo layout

```
/lab
  /vagrant         Vagrantfile + provisioning shell scripts
  /resolver        unbound-vulnerable.conf (Part 3 will add a hardened variant)
  /attacker        spoofer.py, requirements.txt, nginx/index.html
  /victim          demo.sh
  /scripts         reset-lab.sh, run-part1.sh
/docs
  /specs           this design doc
  /screenshots     01-...png through 07-...png
  /captures        poison.pcap
README.md
```

## 5. Victim side and demo flow

The victim is a stock Ubuntu install. `/etc/resolv.conf`:

```
nameserver 192.168.56.20
```

After editing, `chattr +i /etc/resolv.conf` to prevent NetworkManager from
overwriting it on reboot.

### 5.1 `victim/demo.sh`

Non-interactive. Tees output to `docs/screenshots/run-<timestamp>.log`.
Run by `lab/scripts/run-part1.sh` after the spoofer has reported `[+]
poisoned`:

1. **Baseline (run before the spoofer starts):**
   `dig @192.168.56.20 www.target.lab +short` → empty/SERVFAIL.
2. **Proof (run after the spoofer reports success):**
   ```
   dig @192.168.56.20 www.target.lab +short      # → 192.168.56.10
   curl -s http://www.target.lab | head -n 1     # → <h1>YOU'VE BEEN PWNED</h1>
   ```
3. **Assert:** exits non-zero if step 2's `dig` does not return
   `192.168.56.10`. Lets `run-part1.sh` retry or fail cleanly.

### 5.2 Wireshark capture

Started on the resolver VM before the attack. The host-only adapter name
on Ubuntu 22.04 varies (`enp0s8` is typical for VirtualBox's second NIC,
but predictable-naming can produce `enp0s9` etc. depending on adapter
order). The Vagrantfile must pin the adapter order, and the capture script
must discover the right interface:

```
LAB_IF=$(ip -o -4 addr show \
  | awk '$4 ~ /^192\.168\.56\./ {print $2; exit}')
sudo tshark -i "$LAB_IF" -w /tmp/poison.pcap \
            -f 'port 53 or host 192.168.56.10'
```

The pcap is committed to `docs/captures/poison.pcap` and is reused by
Part 2's analysis questions (transaction IDs, ports). No second capture is
needed for Part 2.

### 5.3 Caveat for the report

Because the resolver forwards `target.lab` to a black hole, the pcap shows
the resolver's outbound query followed by *only* the attacker's spoofed
reply — there is no legitimate reply to compete with. The report must
acknowledge this is a simplified topology. In a realistic Kaminsky race the
attacker would also be racing a real authoritative server's response.

## 6. Deliverables

### 6.1 Repo artifacts

- `lab/vagrant/Vagrantfile` — brings up all 3 VMs.
- `lab/resolver/unbound-vulnerable.conf` — weakened config.
- `lab/attacker/spoofer.py` + `requirements.txt` (`scapy==2.5.0` pinned).
- `lab/attacker/nginx/index.html` — PWNED page.
- `lab/victim/demo.sh` — three-step proof.
- `lab/scripts/reset-lab.sh` — flush cache, kill lingering spoofers.
- `lab/scripts/run-part1.sh` — sequences the demo across three SSH sessions
  (start tshark on resolver → start spoofer on attacker → run `demo.sh` on
  victim → on success, kill tshark and copy `poison.pcap` back to the
  host). Fully scripted; supersedes the manual "press Enter" pause that
  appeared in an earlier draft of `demo.sh`. `demo.sh` is now non-interactive
  and exits non-zero if the post-attack `dig` does not return `192.168.56.10`.
- `docs/captures/poison.pcap`.
- `docs/screenshots/` (see 6.2).
- `README.md` — quickstart: `vagrant up && ./lab/scripts/run-part1.sh`.

### 6.2 Screenshots

Named so they slot into the report in order:

1. `01-topology.png` — VirtualBox network diagram or `ip addr` on each VM.
2. `02-resolver-baseline.png` — pre-attack `dig` returning SERVFAIL.
3. `03-spoofer-running.png` — terminal showing the txid sweep + `[+] poisoned`.
4. `04-dig-poisoned.png` — `dig` on victim returning `192.168.56.10`.
5. `05-curl-pwned.png` — `curl` showing the `<h1>YOU'VE BEEN PWNED</h1>` page.
6. `06-wireshark-overview.png` — pcap with trigger query + spoofed flood.
7. `07-wireshark-spoofed-reply.png` — single spoofed packet expanded
    showing matched txid, port, and question section.

### 6.3 Report sections that Part 1 must populate

1. **Lab setup** — topology diagram, VM specs, network.
2. **Resolver configuration** — annotated diff of vulnerable vs. hardened
   defaults; one paragraph per weakened directive (use the table in §3.1).
3. **Threat model** — attacker capabilities (off-path), what the attacker
   knows (resolver IP, fixed source port, that `target.lab` is forwarded).
4. **Attack methodology** — trigger/flood pattern, txid-sweep math, the
   four matched fields the resolver checks (dst IP, dst port, txid,
   question).
5. **Execution & evidence** — the seven screenshots with captions, plus
   the `demo.sh` log.
6. **Caveats** — black-hole simplification (see §5.3), no NS-glue, no real
   Kaminsky race; what would change in a realistic setting.

### 6.4 Demo video (Part 1 segment, ~2 min)

1. Three VM terminals tiled: attacker / resolver-tshark / victim.
2. Run baseline `dig` → SERVFAIL.
3. Start `spoofer.py`, narrate the sweep.
4. Re-run `dig` → poisoned; `curl` → PWNED page.
5. Briefly show Wireshark with the spoofed packet highlighted.

## 7. Build sequence (compressed: May 5 → May 8)

Four working days. Three roles (A, B, C) for a 3-person team; if 2-person,
fold C's work into A and B and expect ~half a day of slip.

### 7.1 Day 1 — Tue May 5: Lab provisioning + resolver

- **Person A (infra):** Install VirtualBox + Vagrant on each host machine.
  Verify Hyper-V is off (`bcdedit /set hypervisorlaunchtype off` on
  Windows hosts that have WSL2/Hyper-V enabled). Write `Vagrantfile` for
  three Ubuntu 22.04 VMs on `192.168.56.0/24`. `vagrant up`. Verify ping
  flows attacker ↔ resolver ↔ victim.
- **Person B (resolver):** Once Person A has the resolver VM up, install
  Unbound, drop in `unbound-vulnerable.conf`, disable systemd-resolved,
  add `forward-zone target.lab → 192.168.56.99`. **First check:** run
  `unbound-checkconf` and confirm zero errors. **Second check:** run
  `sudo tcpdump -i any -nn 'udp and port 53'` on the resolver while
  triggering a query from the victim, and confirm the resolver's outbound
  packet has source port = 33333. If not, switch to the iptables SNAT
  fallback in §3 *today* — do not let this slip into Day 2.
- **Person C (repo + report):** Create the GitHub repo, push files as
  Persons A/B finish them. Draft report sections 1 (Lab setup) and 2
  (Resolver configuration) using this design doc.

**Exit criteria:** `dig @192.168.56.20 www.target.lab` from victim →
SERVFAIL after ~5 s; `02-resolver-baseline.png` captured.

### 7.2 Day 2 — Wed May 6: Spoofer end-to-end

- **Person A:** `spoofer.py` v1 — single-shot Scapy packet, verify on the
  resolver via `tshark` that the 5-tuple matches what Unbound expects.
  Add the trigger thread and the txid sweep. Confirm `[+] poisoned`
  within ~5 s.
- **Person B:** Install Nginx on attacker, drop the PWNED `index.html`.
  Write `victim/demo.sh` and `reset-lab.sh`.
- **Person C:** Draft report sections 3 (Threat model) and 4 (Attack
  methodology). These can be written from the design doc without waiting
  for the script to work.

**Exit criteria:** Full attack chain works end-to-end, once, from a clean
lab restart.

### 7.3 Day 3 — Thu May 7: Capture + report

- **Everyone:** Run the demo three times back-to-back to confirm
  reproducibility.
- Capture all seven screenshots. Capture `poison.pcap` with `tshark`
  running on the resolver during a clean run.
- **Person A:** Polish `spoofer.py` — CLI args, exit codes, comments. The
  script is the centerpiece of the repo and gets read carefully.
- **Person B:** Record the Part 1 demo video segment (2 min, three tiled
  terminals).
- **Person C:** Fill report sections 5 (Execution & evidence) and 6
  (Caveats) using the captured artifacts.

**Exit criteria:** Repo runs cleanly from `vagrant up`. All artifacts in
`docs/`. Report draft complete.

### 7.4 Day 4 — Fri May 8: Submit

- Morning: Final report read-through. Fix any artifact paths in the README.
- Tag repo `part1-complete`. Push to GitHub.
- Upload demo video.
- Submit.

**Buffer:** Half a day on May 8 morning is the only slack. If Day 1 or 2
slips, Day 3's report writing gets squeezed — Person C should run ahead
of A and B since their work doesn't depend on the script working.

## 8. Risks and mitigations

| Risk                                                      | Likelihood | Mitigation                                                                                  |
|-----------------------------------------------------------|------------|---------------------------------------------------------------------------------------------|
| VirtualBox slow / broken on a teammate's Windows 11 host  | Medium     | Verify Hyper-V is off on Day 1 morning. Fallback: VMware Workstation Player.                |
| NetworkManager rewrites `/etc/resolv.conf` on victim      | Medium     | `chattr +i /etc/resolv.conf` after editing. Documented in `victim/demo.sh` setup notes.     |
| Scapy version skew breaks packet crafting                 | Low        | Pin `scapy==2.5.0` in `requirements.txt`. Scapy must run as root.                           |
| Spoof doesn't land within forwarder timeout on Day 2      | Low        | Trigger cadence aligned with negative-cache TTL (~5 s). Don't debug Scapy past 2 hours.     |
| Unbound source-port pinning silently doesn't pin          | Medium     | Verify with tcpdump on Day 1 step 1. Fall back to iptables SNAT (see §3).                   |
| VirtualBox host-only adapter named differently than expected | Medium  | Vagrantfile pins NIC order. `tshark` script auto-discovers via IP prefix (see §5.2).        |
| Vagrant base-box drift breaks Day 3 reproducibility       | Low        | Pin Ubuntu box to `ubuntu/jammy64` at a specific version in the Vagrantfile.                |
| Parts 2 & 3 squeezed by the May 8 deadline                | High       | Acknowledged: this design only covers Part 1. Parts 2/3 get May 9–11 (course deadline 12).  |

## 9. Out of scope (explicit)

- BIND9 configuration. Unbound was chosen.
- Kaminsky NS-glue zone poisoning. Single-record only.
- Real authoritative server racing the attacker. Black hole used instead.
- DNSSEC validation. That's Part 3.
- Phishing UI clone of a real site. The PWNED page is intentionally simple.

## 10. Open questions

None at design time. Anything that surfaces during build goes in the
report's caveats section.
