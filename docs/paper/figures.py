"""Compute every number in the red-teaming paper and render its two figures.

Single source of truth: the .tex files never hardcode a statistic that this script
also computes. Rerun after touching any parameter; paste printed values into the text.

Model (paper Section 7): relevance R(w) = P(w) * I(w) * (1 - D(w))
  P: informed prior that the class materializes in OUR operating context, anchored on
     published defended/undefended attack-success rates (EPSS tradition: population
     base rates, not certainties).
  I: impact 1-5 (operator harm if it materializes).
  D: defendedness 0-1 from our own code audit (what the framework actually covers).
R is a RANKING STATISTIC, not a probability - the paper is explicit about this.

Figure style per charts.md: no top/right spines, dashed grid alpha .2, frameless
legend, no in-axes titles (captions carry them), constrained_layout, explicit
figsize, dpi 200.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import numpy as np

for p in ("/usr/share/fonts/truetype/chinese/NotoSansSC-Regular.ttf",
          "/usr/share/fonts/truetype/chinese/NotoSansSC-Bold.ttf"):
    try:
        fm.fontManager.addfont(p)
    except Exception:
        pass
plt.rcParams["font.sans-serif"] = ["Noto Sans SC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

Z = 1.959963984540054


def wilson(x: int, n: int, z: float = Z):
    """Wilson score interval (centered form). Returns (p_hat, lo, hi)."""
    p = x / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    hw = (z / denom) * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return p, center - hw, center + hw


def pool(points):
    """Beta(1,1) pooling of heterogeneous (x, n) cells: posterior Beta(x+1, n-x+1),
    combined by inverse-variance weighting across cells (NOT one binomial sample)."""
    means, sds = [], []
    for x, n in points:
        m = (x + 1) / (n + 2)
        sd = np.sqrt(m * (1 - m) / (n + 3))
        means.append(m)
        sds.append(sd)
    w = [1 / s ** 2 for s in sds]
    mean = sum(wi * m for wi, m in zip(w, means)) / sum(w)
    sd = 1 / np.sqrt(sum(w))
    return mean, sd


# --- the W1-W14 parameter table ----------------------------------------------------------
# (id, short name, P, I, D, lens)  lens: O=offensive D=defensive-exposure B=dual-use
CLASSES = [
    ("W1",  "Injection vs defended stacks",   0.075, 5, 0.040, "D"),
    ("W2",  "Adaptive jailbreak",             0.500, 5, 0.048, "B"),
    ("W3",  "Swarm cascade",                  0.350, 4, 0.140, "O"),
    ("W4",  "Tool/MCP supply chain",          0.350, 2, 0.400, "D"),
    ("W5",  "Memory poisoning",               0.800, 5, 0.050, "D"),
    ("W6",  "Hidden-context exfiltration",    0.450, 4, 0.280, "B"),
    ("W7",  "Retry-inflated measurement",     0.400, 2, 0.125, "B"),
    ("W8",  "Judge/oracle miscalibration",    0.350, 2, 0.170, "B"),
    ("W9",  "Single-seed reliability",        0.300, 3, 0.180, "B"),
    ("W10", "Cost/turn amplification",        0.300, 3, 0.100, "O"),
    ("W11", "Agentic misuse compliance",      0.350, 3, 0.085, "O"),
    ("W12", "Output-chain second order",      0.380, 4, 0.125, "B"),
    ("W13", "Multilingual erosion",           0.450, 3, 0.130, "O"),
    ("W14", "Supply-chain/model drift",       0.300, 3, 0.000, "D"),
]

rows = []
for wid, name, P, I, D, lens in CLASSES:
    R = P * I * (1 - D)
    rows.append((wid, name, P, I, D, lens, R))
rows.sort(key=lambda r: -r[6])

print("=== relevance ranking R(w) = P*I*(1-D) ===")
for rank, (wid, name, P, I, D, lens, R) in enumerate(rows, 1):
    print(f"{rank:2d}. {wid:4s} {name:32s} P={P:.3f} I={I} D={D:.3f} lens={lens}  R={R:.2f}")

# --- the two evidence pools ---------------------------------------------------------------
undef = pool([(683, 2312)])
defnd = pool([(93, 1258)])
print(f"\nundefended pool: mean={undef[0]:.3f} sd={undef[1]:.4f}")
print(f"defended   pool: mean={defnd[0]:.3f} sd={defnd[1]:.4f}")
print(f"defense ratio: {undef[0]/defnd[0]:.2f}x")

print("\n=== Wilson table (worked cells) ===")
cells = [
    ("undefended pool", 683, 2312), ("defended pool", 93, 1258),
    ("AgentDojo-style undefended cell", 79, 229), ("defended cell (tool-firewall)", 17, 219),
    ("multilingual EN cell", 156, 200), ("multilingual low-resource cell", 162, 200),
    ("wildcard cell 3/20", 3, 20),
]
for name, x, n in cells:
    p, lo, hi = wilson(x, n)
    print(f"{name:34s} {x:4d}/{n:5d}  p={p:.3f}  CI=[{lo:.3f}, {hi:.3f}]")

print("\n=== rule of three ===")
for n in (30, 60, 300, 3000):
    print(f"n={n:5d}  zero-event 95% upper bound = {1 - 0.05 ** (1 / n):.4f}")

print("\n=== retry inflation ===")
for p, k in ((0.03, 20), (0.05, 5), (0.10, 10)):
    print(f"p={p:.2f} k={k:2d}  session={1 - (1 - p) ** k:.3f}  "
          f"back-out={1 - (1 - (1 - (1 - p) ** k)) ** (1 / k):.4f}")

print("\n=== at-least-one arithmetic across the 14 classes ===")
ps = [P for _, _, P, _, _, _, _ in rows]
expected = sum(ps)
p_any = 1 - np.prod([1 - p for p in ps])
p_any_half = 1 - np.prod([1 - p / 2 for p in ps])
print(f"expected material classes per engagement: {expected:.2f} / {len(ps)}")
print(f"P(at least one | INDEPENDENCE) ~ {p_any:.5f}   Bonferroni bound min(1, sum) = {min(1, expected):.2f}")
print(f"P(at least one | independence, every prior HALVED) ~ {p_any_half:.5f}")
print("note: positive correlation between classes pushes the true value BELOW the independence figure")

print("\n=== sensitivity: deterministic all-up / all-down +/-0.10 on P ===")
def rank_with(delta):
    rs = []
    for wid, name, P, I, D, lens, _ in rows:
        Pm = min(1.0, max(0.0, P + delta))
        rs.append((wid, Pm * I * (1 - D)))
    rs.sort(key=lambda r: -r[1])
    return [w for w, _ in rs[:3]], [w for w, _ in rs]
base3, base_all = rank_with(0)
up3, up_all = rank_with(+0.10)
dn3, dn_all = rank_with(-0.10)
print(f"base top3: {base3}   P+0.10: {up3}   P-0.10: {dn3}")
print(f"base full: {base_all}")
print(f"up   full: {up_all}")
print(f"down full: {dn_all}")
moved_up = [w for w in up_all if up_all.index(w) != base_all.index(w)]
moved_dn = [w for w in dn_all if dn_all.index(w) != base_all.index(w)]
print(f"ranks changed at +0.10: {moved_up}")
print(f"ranks changed at -0.10: {moved_dn}")

print("\n=== sensitivity: Monte Carlo +/-0.10 on P and D (10,000 draws, seed 42) ===")
rng = np.random.default_rng(42)
N = 10_000
base_ranks_3_10 = set(r[0] for r in rows[2:10])
w5_r1 = head2 = set310 = w12w6_top4 = 0
for _ in range(N):
    rs_mc = []
    for wid, name, P, I, D, lens, _ in rows:
        Pm = min(0.95, max(0.02, P + rng.uniform(-0.10, 0.10)))
        Dm = min(1.0, max(0.0, D + rng.uniform(-0.10, 0.10)))
        rs_mc.append((wid, Pm * I * (1 - Dm)))
    rs_mc.sort(key=lambda r: -r[1])
    ids = [w for w, _ in rs_mc]
    if ids[0] == "W5":
        w5_r1 += 1
    if set(ids[:2]) == {"W5", "W2"}:
        head2 += 1
    if set(ids[2:10]) == base_ranks_3_10:
        set310 += 1
    if {"W12", "W6"} <= set(ids[:4]):
        w12w6_top4 += 1
print(f"W5 holds rank 1:              {w5_r1/N:.1%}")
print(f"{{W5,W2}} hold top 2 as a set: {head2/N:.1%}")
print(f"ranks 3-10 preserved as a set: {set310/N:.1%}")
print(f"W12 and W6 both inside top 4: {w12w6_top4/N:.1%}")


# --- figures ------------------------------------------------------------------------------

def style_ax(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, linestyle="--", alpha=0.2)
    ax.set_axisbelow(True)


# Figure 1: published ASR anchors - four groups, hollow = defended arm
fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=200, constrained_layout=True)
groups = {
    "Automated jailbreak":   [("GCG", 0.60, 0), ("PAIR", 0.43, 0), ("R2D2", 0.88, 0)],
    "Indirect prompt inj.":  [("InjecAgent", 0.34, 0), ("AgentDojo", 0.345, 0),
                              ("AgentDojo+CaMeL", 0.068, 1), ("AgentDojo+TD", 0.080, 1)],
    "Memory poisoning":      [("PoisonedRAG@5", 0.90, 0), ("AgentPoison<0.1%", 0.80, 0)],
    "Multilingual shift":    [("EN base", 0.78, 0), ("Low-res avg", 0.809, 0),
                              ("Guard delta", 0.27, 1)],
}
palette = {"Automated jailbreak": "#B4554D", "Indirect prompt inj.": "#5A7FA8",
           "Memory poisoning": "#8B7E5A", "Multilingual shift": "#5A8A6E"}
x0 = 0.0
ticks, labels = [], []
for gname, items in groups.items():
    for label, v, defended in items:
        ax.bar(x0, v, width=0.62, color=palette[gname],
               fill=not defended, edgecolor=palette[gname],
               linewidth=1.4 if defended else 0)
        ticks.append(x0)
        labels.append(label)
        x0 += 1
    x0 += 0.9
ax.set_xticks(ticks)
ax.set_xticklabels(labels, rotation=38, ha="right", fontsize=7.6)
ax.set_ylabel("published attack-success rate", fontsize=9)
ax.set_ylim(0, 1.0)
style_ax(ax)
handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette.values()]
ax.legend(handles, list(palette), frameon=False, fontsize=8, loc="upper left",
          bbox_to_anchor=(0.01, 0.99))
fig.savefig("fig_asr.png")
plt.close(fig)

# Figure 2: relevance ranking
fig, ax = plt.subplots(figsize=(7.2, 4.8), dpi=200, constrained_layout=True)
ids = [r[0] for r in rows][::-1]
vals = [r[6] for r in rows][::-1]
names = [r[1] for r in rows][::-1]
lens = [r[5] for r in rows][::-1]
cmap = {"O": "#B4554D", "D": "#5A7FA8", "B": "#8B7E5A"}
bars = ax.barh(range(len(ids)), vals, color=[cmap[l] for l in lens], height=0.66)
ax.set_yticks(range(len(ids)))
ax.set_yticklabels([f"{i}  {n}" for i, n in zip(ids, names)], fontsize=8)
for y, v in enumerate(vals):
    ax.text(v + 0.04, y, f"{v:.2f}", va="center", fontsize=7.4, color="#444444")
ax.set_xlabel("relevance R(w) = P x I x (1-D)", fontsize=9)
ax.set_xlim(0, 4.3)
style_ax(ax)
handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in cmap.values()]
ax.legend(handles, ["O offensive", "D defensive exposure", "B dual-use"],
          frameon=False, fontsize=8, loc="lower right", bbox_to_anchor=(0.99, 0.04))
fig.savefig("fig_relevance.png")
plt.close(fig)

print("\nfigures written: fig_asr.png, fig_relevance.png")
