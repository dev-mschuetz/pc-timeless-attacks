import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

labels = ["0 ns", "50 ns", "210 ns", "360 ns", "510 ns", "750 ns", "2.3 µs", "23 µs"]
sent2  = [2.96, 3.08, 3.00, 4.16, 4.44, 7.52, 23.16, 99.32]
pvals  = [0.331, 0.300, 0.194, 0.0385, 0.0462, 7.09e-05, 1.41e-56, 0.0]

def bar_color(p):
    if p > 0.05:
        return "#9ca3af"
    if p > 0.01:
        return "#f59e0b"
    return "#10b981"

colors = [bar_color(p) for p in pvals]

fig, ax = plt.subplots(figsize=(9, 4.5))
fig.patch.set_facecolor("#ffffff")
ax.set_facecolor("#f8fafc")

x = np.arange(len(labels))
bars = ax.bar(x, sent2, color=colors, width=0.6, zorder=3)

for bar, p in zip(bars, pvals):
    h = bar.get_height()
    if p == 0.0:
        label = "p ≈ 0"
    elif p < 1e-10:
        label = f"p=1e{int(np.floor(np.log10(p)))}"
    elif p < 0.001:
        label = f"p={p:.4f}"
    else:
        label = f"p={p:.2f}"
    offset = max(h + 1.5, 5.5)
    ax.text(bar.get_x() + bar.get_width() / 2, offset, label,
            ha="center", va="bottom", fontsize=7.5, color="#1e293b")

ax.set_xticks(x)
ax.set_xticklabels(labels, color="#1e293b", fontsize=9)
ax.set_ylabel("sent-2nd win rate (%)", color="#475569", fontsize=10)
ax.set_xlabel("timing asymmetry (delay added to /slow)", color="#475569", fontsize=10)
ax.set_title("Timeless Timing Attack — detection by timing asymmetry\n(sent-2nd win rate: how often /fast wins when sent second)",
             color="#0f172a", fontsize=11, pad=12)

ax.set_ylim(0, 108)
ax.tick_params(colors="#1e293b")
for spine in ax.spines.values():
    spine.set_edgecolor("#cbd5e1")
ax.grid(axis="y", color="#e2e8f0", linewidth=0.6, zorder=0)

patches = [
    mpatches.Patch(color="#9ca3af", label="p > 0.05 (not significant)"),
    mpatches.Patch(color="#f59e0b", label="p < 0.05 (borderline)"),
    mpatches.Patch(color="#10b981", label="p < 0.01 (significant)"),
]
ax.legend(handles=patches, loc="upper left", fontsize=8,
          facecolor="#ffffff", edgecolor="#cbd5e1", labelcolor="#1e293b")

plt.tight_layout()
plt.savefig("results/detection_chart.png", format="png", dpi=150, facecolor=fig.get_facecolor())
print("saved results/detection_chart.png")
