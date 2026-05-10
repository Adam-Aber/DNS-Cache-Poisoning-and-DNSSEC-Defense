"""Generate PNG charts comparing Part 1 (no DNSSEC) vs Part 3 (DNSSEC)."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

OUT = Path(__file__).parent.parent / "screenshots" / "png"
OUT.mkdir(parents=True, exist_ok=True)

NAVY, RED, GREEN, GOLD = "#1a3050", "#c93a3a", "#2e8b57", "#e0a000"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.titleweight": "bold",
})

# ----- Part 1 vs Part 3 outcome -----
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

# Left: spoofs sent
labels = ["Part 1\n(validator off)", "Part 3\n(validator on)"]
spoofs = [23828, 401223]
poisoned_at = [4.2, None]   # seconds; None = never
flood_color = [NAVY, NAVY]

bars = axes[0].bar(labels, spoofs, color=flood_color, edgecolor="white")
axes[0].set_ylabel("Spoofed replies sent")
axes[0].set_title("Spoof volume: Part 3 ran 17× more — yet failed")
for b, v in zip(bars, spoofs):
    axes[0].text(b.get_x() + b.get_width()/2, v + 8000, f"{v:,}",
                 ha="center", fontsize=10, color=NAVY, fontweight="bold")
axes[0].set_ylim(0, max(spoofs) * 1.15)

# Right: poisoning result
results = ["Part 1\nresolver", "Part 3\nresolver"]
status = [1, 0]  # 1 = poisoned, 0 = clean
colors = [RED, GREEN]
b2 = axes[1].bar(results, [1, 1], color=colors, edgecolor="white")
axes[1].set_ylim(0, 1.4)
axes[1].set_yticks([])
axes[1].set_title("Cache outcome")
for b, label, color in zip(b2,
                            ["POISONED\nin 4.2 s", "CLEAN\nfor 60 s+"],
                            ["white", "white"]):
    axes[1].text(b.get_x() + b.get_width()/2, 0.5, label,
                 ha="center", va="center", fontsize=14, color=color,
                 fontweight="bold")

plt.tight_layout()
plt.savefig(OUT / "12-1-part1-vs-part3.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 12-1-part1-vs-part3.png")

# ----- Validator's behavior over time -----
# Resolver outbound queries during Part 3:
# 9 target.lab DNSKEY (type 48), 5 _ta-1973.target.lab NULL (type 10), 1 www.target.lab A (type 1)
labels = ["DNSKEY fetch\n(target.lab)", "Keytag signal\n(_ta-1973.target.lab)",
          "Original A query\n(www.target.lab)"]
counts = [9, 5, 1]
colors = [GOLD, NAVY, GREEN]

fig, ax = plt.subplots(figsize=(8, 4.2))
bars = ax.barh(labels, counts, color=colors, edgecolor="black")
for b, v in zip(bars, counts):
    ax.text(v + 0.2, b.get_y() + b.get_height()/2, str(v),
            va="center", fontsize=11, color="black", fontweight="bold")
ax.set_xlabel("Outbound queries from resolver to forwarder (192.168.56.99)")
ax.set_title("What the validator did: kept retrying to fetch the DNSKEY")
ax.set_xlim(0, max(counts) * 1.25)
plt.tight_layout()
plt.savefig(OUT / "12-2-validator-outbound.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 12-2-validator-outbound.png")

# ----- Defense layer comparison -----
fig, ax = plt.subplots(figsize=(10, 4.5))
layers = ["Wire-tuple match\n(dst IP, port, qname, txid)",
          "Bailiwick check\n(harden-glue)",
          "DNSSEC validation\n(RRSIG check vs trust anchor)"]
attacker_can = [
    ("Defeat with brute force\nin ~5 s on this lab", RED, 0.85),
    ("Disabled in lab\n(harden-glue: no)", GOLD, 0.85),
    ("Cryptographic — cannot\nbe defeated by brute force", GREEN, 0.85),
]
ax.set_xlim(0, 10)
ax.set_ylim(-0.5, 3)
ax.axis("off")
ax.set_title("DNS reply-validation layers — only DNSSEC stops a brute-force off-path attacker", pad=15)

for i, (layer, (text, color, alpha)) in enumerate(zip(layers, attacker_can)):
    y = 2.5 - i * 1.0
    ax.add_patch(mpatches.Rectangle((0.2, y - 0.32), 3.5, 0.64, facecolor=NAVY, alpha=0.15, edgecolor=NAVY))
    ax.text(2.0, y, layer, ha="center", va="center", fontsize=11, color=NAVY, fontweight="bold")
    ax.add_patch(mpatches.FancyArrow(3.7, y, 0.6, 0, head_width=0.18, head_length=0.18, color="#333"))
    ax.add_patch(mpatches.Rectangle((4.5, y - 0.32), 5.3, 0.64, facecolor=color, alpha=alpha, edgecolor="black"))
    ax.text(7.15, y, text, ha="center", va="center", fontsize=10.5, color="white", fontweight="bold")

plt.tight_layout()
plt.savefig(OUT / "12-3-defense-layers.png", dpi=140, bbox_inches="tight")
plt.close(fig)
print("wrote 12-3-defense-layers.png")

print(f"\nAll Part 3 charts in {OUT}")
