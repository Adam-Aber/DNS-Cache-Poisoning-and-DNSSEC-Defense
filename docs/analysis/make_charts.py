"""Generate PNG charts from the Part 2 pcap analysis CSVs."""
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

HERE = Path(__file__).parent
OUT = HERE.parent / "screenshots" / "png"
OUT.mkdir(parents=True, exist_ok=True)

NAVY = "#1a3050"
RED = "#c93a3a"
GREEN = "#2e8b57"
GRAY = "#888888"

# Common style
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.titleweight": "bold",
})

# ----- Chart 1: spoof rate per second -----
secs, pkts = [], []
with open(HERE / "E-spoof-rate-per-second.csv") as f:
    next(f)  # header
    for line in f:
        s, p = line.strip().split(",")
        secs.append(int(s))
        pkts.append(int(p))

fig, ax = plt.subplots(figsize=(8, 4))
bars = ax.bar(secs, pkts, color=NAVY, edgecolor="white")
# Mark the moment of poison (~3.3 s) with a vertical line
ax.axvline(3.297, color=RED, linestyle="--", linewidth=2, label="poison landed (t = 3.297 s)")
ax.set_xlabel("Capture second")
ax.set_ylabel("Spoofed packets sent")
ax.set_title("Spoof flood rate — sustained ~5,800 pps until poison detected")
for b, v in zip(bars, pkts):
    ax.text(b.get_x() + b.get_width()/2, v + 80, f"{v:,}",
            ha="center", va="bottom", fontsize=9, color=NAVY)
ax.legend(loc="upper right", frameon=False)
ax.set_ylim(0, max(pkts) * 1.15)
plt.tight_layout()
plt.savefig(OUT / "08-3-spoof-rate.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 08-3-spoof-rate.png")

# ----- Chart 2: race-window analysis -----
# Each trigger fires at t_i, opens a 5-second window. Flood sweeps
# txid 0..65535 sequentially at ~5800 pps. We mark the txid each
# trigger asks for and shade where the flood passes through it.
triggers = [
    (1, 0.047, 0xa6bb, 42683),
    (2, 0.427, 0xab44, 43844),
    (3, 0.808, 0x762c, 30252),
    (4, 1.563, 0x0c87, 3207),
    (5, 2.319, 0x492c, 18732),
]
RATE = 5800             # packets per sec sustained
WINDOW = 5.0            # forwarder timeout
SWEEP_LEN = 65536 / RATE
LANDED_FRAME_T = 3.297  # winning spoof
LANDED_TXID = 0x492c
FLOOD_STOPPED_T = 3.6   # spoofer detected poison; flood drops to ~zero
FLOOD_MAX_TXID = int(RATE * FLOOD_STOPPED_T)  # last txid the flood reached

fig, ax = plt.subplots(figsize=(10, 5.2))
ax.set_xlabel("Capture time (s)")
ax.set_ylabel("Trigger # (resolver outbound query)")
ax.set_yticks([t[0] for t in triggers])
ax.set_xlim(-0.2, 11)
ax.set_ylim(0.5, 5.7)
ax.set_title("Race-window timing — only trigger 5 had its txid swept inside the window")

for n, t, txid_hex, txid_int in triggers:
    # Trigger window
    ax.barh(n, WINDOW, left=t, height=0.45, color=NAVY, alpha=0.18,
            edgecolor=NAVY, linewidth=0.5)
    # First-sweep arrival of this txid (if any)
    first_pass = txid_int / RATE
    # Next-sweep arrival
    next_pass = first_pass + SWEEP_LEN
    # Did the first sweep happen before the trigger fired?
    if first_pass < t:
        # Flood already passed this txid before the window opened
        if next_pass <= FLOOD_STOPPED_T and next_pass <= t + WINDOW:
            color, marker, plot_x = GREEN, "o", next_pass
            label = f"sweep 2 reaches @ t={next_pass:.2f}s"
        else:
            color, marker, plot_x = RED, "X", t + WINDOW + 1.0
            label = (f"sweep 1 already passed @ t={first_pass:.2f}s\n"
                     f"flood ended before next sweep")
    else:
        # First sweep is still ahead at trigger time
        if first_pass <= FLOOD_STOPPED_T and first_pass <= t + WINDOW:
            color, marker, plot_x = GREEN, "o", first_pass
            label = f"flood reaches @ t={first_pass:.2f}s"
        else:
            color, marker, plot_x = RED, "X", t + WINDOW + 1.0
            label = (f"flood stopped @ t={FLOOD_STOPPED_T}s\n"
                     f"never reached txid {txid_int:,}")
    ax.scatter([plot_x], [n], s=130, color=color, marker=marker, zorder=5,
               edgecolor="black", linewidth=0.7)
    ax.annotate(f"txid {txid_hex} ({txid_int:,})\n{label}",
                xy=(plot_x, n), xytext=(plot_x + 0.15, n + 0.18),
                fontsize=8.5, color=color)
    # trigger marker
    ax.scatter([t], [n], marker="|", s=200, color=NAVY)
    ax.text(t, n - 0.32, f"t={t:.2f}s", fontsize=8, ha="center", color=NAVY)

# Show where the flood stopped
ax.axvline(FLOOD_STOPPED_T, color="#888", linestyle=":", linewidth=1.5,
           label=f"flood ended @ t={FLOOD_STOPPED_T}s (poison detected)")

# Star the winning landing
ax.scatter([LANDED_FRAME_T], [5], marker="*", s=420, color="#ffd400",
           edgecolor="black", linewidth=1.0, zorder=10,
           label=f"winning spoof landed @ t={LANDED_FRAME_T}s, txid 0x{LANDED_TXID:04x}")

handles = [
    mpatches.Patch(facecolor=NAVY, alpha=0.18, label="5-s race window"),
    plt.Line2D([0], [0], marker="o", color=GREEN, label="flood swept txid in window",
               markersize=10, linewidth=0),
    plt.Line2D([0], [0], marker="X", color=RED, label="flood never reached txid",
               markersize=10, linewidth=0),
    plt.Line2D([0], [0], marker="*", color="#ffd400", label="winning spoof matched",
               markersize=18, linewidth=0, markeredgecolor="black"),
    plt.Line2D([0], [0], color="#888", linestyle=":", label="flood ended"),
]
ax.legend(handles=handles, loc="lower right", fontsize=9, frameon=True)
ax.invert_yaxis()
plt.tight_layout()
plt.savefig(OUT / "08-4-race-windows.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 08-4-race-windows.png")

# ----- Chart 3: source-port histogram (the entropy collapse) -----
fig, ax = plt.subplots(figsize=(8, 3.5))
# Hardened side
ax.barh(["Hardened\n(RFC 5452)"], [60000 - 32768 + 1], left=32768,
        color=GREEN, alpha=0.7, edgecolor="black",
        label="Source port range used (hardened)")
# Lab side
ax.barh(["This lab"], [1], left=33333, color=RED,
        edgecolor="black", linewidth=2,
        label="Source port range used (lab)")
ax.set_xlim(0, 65535)
ax.set_xlabel("UDP source port (0–65535)")
ax.set_title("Source-port entropy — hardened resolver vs. this lab")
ax.legend(loc="upper right", fontsize=9)
# Add text annotation
ax.text(33333, 1.32, "pinned at 33333\n(0 bits of entropy)", color=RED,
        fontsize=10, ha="center", fontweight="bold")
ax.text((32768 + 60999)/2, 0.32, "32 768 – 60 999 (~28 000 ports, ~14.8 bits)",
        color=GREEN, fontsize=10, ha="center", fontweight="bold")
plt.tight_layout()
plt.savefig(OUT / "08-1-port-entropy.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 08-1-port-entropy.png")

# ----- Chart 4: entropy budget -----
fields = ["Dst IP", "Dst port", "qname/0x20", "Txid", "TOTAL"]
hardened = [0, 14.8, 5, 16, 35.8]   # rough bits
lab = [0, 0, 0, 16, 16]
x = range(len(fields))
fig, ax = plt.subplots(figsize=(8, 4.2))
w = 0.36
ax.bar([i - w/2 for i in x], hardened, w, color=GREEN, label="Hardened (RFC 5452 + 0x20)")
ax.bar([i + w/2 for i in x], lab, w, color=RED, label="This lab (deliberately weakened)")
for i, (h, l) in enumerate(zip(hardened, lab)):
    ax.text(i - w/2, h + 0.4, f"{h}", ha="center", color=GREEN, fontsize=9)
    ax.text(i + w/2, l + 0.4, f"{l}", ha="center", color=RED, fontsize=9)
ax.set_xticks(list(x))
ax.set_xticklabels(fields)
ax.set_ylabel("Effective entropy (bits)")
ax.set_title("Entropy the off-path attacker must defeat")
ax.legend(frameon=False)
ax.set_ylim(0, max(hardened) * 1.15)
plt.tight_layout()
plt.savefig(OUT / "09-entropy-budget.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 09-entropy-budget.png")

print(f"\nAll charts in {OUT}")
