# DNS Cache Poisoning and DNSSEC Defense

Demo video: https://drive.google.com/file/d/1V1qc9Af7FlEa-5M5hNyLDimg0XmVPhLY/view?usp=sharing

A complete, reproducible 3-VM virtual lab that:

1. **Part 1** — performs an off-path DNS cache poisoning attack against a deliberately-weakened Unbound resolver
2. **Part 2** — analyzes the pcap to quantify the entropy collapse and explain the race-window timing
3. **Part 3** — re-runs the same attack against the same resolver with **DNSSEC validation enabled**, and demonstrates that 401,223 spoofed packets fail to poison the cache

Built for the Network Security course project, May 2026.

## Headline result

| | Part 1 (vulnerable) | Part 3 (DNSSEC) |
|---|---:|---:|
| Spoofs sent | 23,828 | **401,223** |
| Spoofs accepted | 1 | **0** |
| Time to poison | 4.2 s | never (60 s+ tested) |
| `dig www.target.lab` returned | `192.168.56.10` (attacker) | nothing |

## Architecture

Three Ubuntu 22.04 VMs on internal network `lab_intnet` (`192.168.56.0/24`):

| VM | IP | Role |
|---|---|---|
| `attacker` | `192.168.56.10` | runs `spoofer.py` (Scapy raw-socket flood) and Nginx PWNED page |
| `resolver` | `192.168.56.20` | weakened Unbound 1.13.1 (source port pinned to 33333) |
| `victim` | `192.168.56.30` | `/etc/resolv.conf` pinned to resolver |

Full design + decisions: [`docs/superpowers/specs/2026-05-05-dns-cache-poisoning-part1-design.md`](docs/superpowers/specs/2026-05-05-dns-cache-poisoning-part1-design.md)

## Quickstart

**Prerequisites:**
- VirtualBox 7.x
- Vagrant ≥ 2.4
- Hyper-V disabled on Windows hosts (`bcdedit /set hypervisorlaunchtype off` then reboot)

**Run Part 1 (attack):**

```
cd lab/vagrant && vagrant up
cd ../scripts && bash run-part1.sh
```

Expected last line: `[+] Part 1 demo SUCCESS  (pcap → docs/captures/poison.pcap)`. Lands the poison in 0.4–4.2 s.

**Run Part 3 (DNSSEC defense):** see [`docs/report/part3-report.pdf`](docs/report/part3-report.pdf) Appendix B for the steps to install BIND tools, generate the trust anchor, swap to `unbound-hardened.conf`, and re-run the same script. The spoofer will report `[-] FAILED to poison within 60s`.

## Reports

All reports are pre-rendered PDFs with embedded charts:

- **[`docs/report/parts1-2-3-report.pdf`](docs/report/parts1-2-3-report.pdf)** — combined master report (recommended)
- [`docs/report/part1-report.pdf`](docs/report/part1-report.pdf) — Part 1 only (cache poisoning attack)
- [`docs/report/part2-report.pdf`](docs/report/part2-report.pdf) — Part 2 (pcap analysis with charts)
- [`docs/report/part3-report.pdf`](docs/report/part3-report.pdf) — Part 3 (DNSSEC defense)

## Repo layout

```
lab/
  vagrant/        Vagrantfile + provisioners
  resolver/       unbound-vulnerable.conf, unbound-hardened.conf, snat-fallback.sh
  attacker/       spoofer.py, requirements.txt, test_spoofer.py, nginx/
  victim/         demo.sh
  scripts/        run-part1.sh, reset-lab.sh, _ssh-helper.sh, discover-iface.sh
docs/
  superpowers/    design spec, implementation plan
  screenshots/
    png/          embedded chart images (matplotlib)
    *.txt         tshark + dig + curl terminal logs
  captures/
    poison.pcap          Part 1 capture (3.2 MB, 23,843 DNS packets)
    poison-dnssec.pcap   Part 3 capture (54 MB, 401,265 DNS packets)
  analysis/       CSVs/TSVs from tshark, plus the chart-generation scripts
  report/         {part1,part2,part3,parts1-2-3}-report.pdf
```

## Centerpiece artifact: `lab/attacker/spoofer.py`

Two-thread Python 3 + Scapy script that builds a single template DNS reply (UDP checksum disabled), then in a tight loop rewrites only the 2 transaction-ID bytes and sends through a persistent `IPPROTO_RAW` socket. Sustains ~5,800 spoofs/sec, exhausting the 16-bit txid space in well under one ~5-second forwarder-timeout window.

## Re-running the demo

```
bash lab/scripts/reset-lab.sh    # restart unbound, kill stale processes
bash lab/scripts/run-part1.sh    # full demo
```

## Tearing down

```
cd lab/vagrant && vagrant destroy -f
```
