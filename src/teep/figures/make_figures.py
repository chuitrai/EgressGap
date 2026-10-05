"""Figures 2 and 3 for the ICC 2027 paper.

Inputs (export from the measurement pipeline, one row per item):
  data/cotenant_per_policy.csv   policy_id,cotenant_before,cotenant_after
  data/destination_freq.csv      destination,n_repos

Outputs: fig2_reachability.pdf, fig3_coverage.pdf (vector, fonts embedded).
Run: python make_figures.py
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt

# Resolve paths relative to the repo so it runs from any cwd, and drop the
# PDFs next to figures_latex.tex in ../report so they are Overleaf-ready.
from teep import paths as _P
DATA = _P.data("data")
OUTDIR = _P.REPORT                                      # sibling report/ folder (TEEP_REPORT to override)

COL_W = 3.5          # IEEE single-column width, inches
# Chosen for a large luminance gap so the two series stay distinct in
# grayscale/B&W print: dark navy (~0.25 luma) vs light amber (~0.68).
# Hatch (bars) and dashed line (CDF) reinforce the distinction on top of hue.
BEFORE = "#0d3b5c"   # I  (declared) -- dark
AFTER = "#f4a259"    # I' (tightened) -- light
INK = "#222222"
GRID = "#d9d9d9"

mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "STIXGeneral"],
    "mathtext.fontset": "stix",
    "font.size": 6,          # ~75% of previous (was 8) per advisor
    "axes.labelsize": 6.5,
    "xtick.labelsize": 5.5,
    "ytick.labelsize": 5.5,
    "legend.fontsize": 5.5,
    "axes.linewidth": 0.6,
    "axes.edgecolor": INK,
    "axes.labelcolor": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.5,
    "axes.axisbelow": True,
    "legend.frameon": False,
    "pdf.fonttype": 42,   # embed TrueType subsets; never Type 3
    "ps.fonttype": 42,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})


def panel_label(ax, text):
    """IEEE-style subfigure label centred under the panel."""
    ax.text(0.5, -0.36, text, transform=ax.transAxes, ha="center", va="top")


def ecdf(values):
    x = np.sort(np.asarray(values))
    y = np.arange(1, len(x) + 1) / len(x)
    return x, y


def fig2(cotenant):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(COL_W, 1.75),
                                   gridspec_kw={"width_ratios": [1.05, 1], "wspace": 0.45})

    # (a) channel prevalence before / after tightening -- values from Table I
    groups = ["Any\n(strict)", "Shared\naddress", "Open\nwildcard"]
    before = [66.6, 56.3, 15.3]
    after = [36.9, 36.8, 0.1]
    x = np.arange(len(groups))
    w = 0.36
    b1 = ax1.bar(x - w / 2 - 0.01, before, w, color=BEFORE, label=r"$I$ (declared)")
    b2 = ax1.bar(x + w / 2 + 0.01, after, w, color=AFTER, hatch="////",
                 edgecolor=INK, linewidth=0.4, label=r"$I'$ (tightened)")
    for bars in (b1, b2):
        for r in bars:
            ax1.text(r.get_x() + r.get_width() / 2, r.get_height() + 1.5,
                     f"{r.get_height():.1f}", ha="center", va="bottom", fontsize=5, color=INK)
    ax1.set_xticks(x, groups)
    ax1.set_ylabel("Policies with channel (%)")
    ax1.set_ylim(0, 90)
    ax1.grid(axis="x", visible=False)
    ax1.legend(loc="upper right", handlelength=1.2, borderaxespad=0)
    panel_label(ax1, "(a)")

    # (b) ECDF of co-tenant names reachable per policy (policies with >= 1)
    pre = cotenant["cotenant_before"]
    post = cotenant["cotenant_after"]
    pre, post = pre[pre > 0], post[post > 0]
    for vals, color, ls, lab in ((pre, BEFORE, "-", r"$I$"), (post, AFTER, "--", r"$I'$")):
        xs, ys = ecdf(vals)
        ax2.step(xs, ys, where="post", color=color, linestyle=ls, linewidth=1.2, label=lab)
    ax2.set_xscale("log")
    ax2.set_xlabel("Co-tenants reachable")
    ax2.set_ylabel("CDF of policies")
    ax2.set_ylim(0, 1.02)
    ax2.legend(loc="upper left", handlelength=1.8, borderaxespad=0.2)
    panel_label(ax2, "(b)")

    fig.savefig(OUTDIR / "fig2_reachability.pdf")
    print(f"fig2: plotted {len(pre)} policies before and {len(post)} after "
          f"(zero-co-tenant policies excluded; say so in the caption)")
    print(f"      medians {np.median(pre):.0f} / {np.median(post):.0f}, "
          f"max {pre.max()} / {post.max()}  -- must match 7 / 3 and 6,307 / 313")


def fig3(freq):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(COL_W, 1.75),
                                   gridspec_kw={"width_ratios": [1, 1.15], "wspace": 0.55})

    # (a) rank-frequency of declared destinations
    n = np.sort(freq["n_repos"].to_numpy())[::-1]
    rank = np.arange(1, len(n) + 1)
    ax1.loglog(rank, n, color=BEFORE, linewidth=1.2)
    ax1.axhline(5, color=INK, linewidth=0.6, linestyle=":")
    share = (n < 5).mean() * 100   # printed for the caption; NOT drawn on the figure
    ax1.set_xlabel("Destination rank")
    ax1.set_ylabel("Repositories")
    panel_label(ax1, "(a)")

    # (b) coverage test outcome over the 545 repositories (Sec. IV-B)
    labels = ["Covered", "Fallback-rule\nartifact", "No S1 rule"]
    counts = [9, 19, 517]
    # Distinct fill + hatch per bar so the three stay apart in greyscale print.
    bar_colors = ["#9aa0a6", AFTER, BEFORE]      # grey / orange / blue
    bar_hatch = ["", "xxxx", ""]
    y = np.arange(len(labels))
    bars = ax2.barh(y, counts, height=0.55, color=bar_colors,
                    edgecolor=INK, linewidth=0.4)
    for bar, h in zip(bars, bar_hatch):
        bar.set_hatch(h)
    for yi, c in zip(y, counts):
        ax2.text(c + 8, yi, f"{c}", va="center", fontsize=5, color=INK)
    ax2.set_yticks(y, labels)
    ax2.set_xlim(0, 600)
    ax2.set_xlabel("Repositories ($n{=}545$)")
    ax2.grid(axis="y", visible=False)
    panel_label(ax2, "(b)")

    fig.savefig(OUTDIR / "fig3_coverage.pdf")
    print(f"fig3: {len(n)} destinations, {share:.1f}% in < 5 repos "
          f"-- must match 1,803 and 84%")


if __name__ == "__main__":
    try:
        cot = pd.read_csv(DATA / "cotenant_per_policy.csv")
        frq = pd.read_csv(DATA / "destination_freq.csv")
    except FileNotFoundError as e:
        sys.exit(f"missing input: {e.filename}\n"
                 f"  -> run first:  python results/export_figure_csvs.py")
    fig2(cot)
    fig3(frq)
