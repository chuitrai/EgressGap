#!/usr/bin/env python3
"""
jaccard_sweep.py - Quet toan bo dai nguong Jaccard tu 0.01 den 0.99 (buoc 0.01)
de danh gia do nhay cua N hieu dung (Effective Sample Size).

CAI DAT:
    pip install pandas matplotlib

CHAY:
    python jaccard_sweep.py
    # hoac: uv run python jaccard_sweep.py

DAU RA:
    analysis/tables/t_jaccard_sweep.csv  (Du lieu day du 99 moc)
    analysis/tables/t_jaccard_sweep.md   (Bang markdown)
    analysis/tables/t_jaccard_sweep.tex  (Bang LaTeX cho paper)
    analysis/figures/f_jaccard_sweep.png (Bieu do duong cong do nhay)
"""

from teep import paths as _P
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("Thieu pandas. Chay: pip install pandas matplotlib")

HAVE_PLT = True
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    HAVE_PLT = False

DATA = _P.data("data")
OUT = _P.data("analysis")
TBL = OUT / "tables"
FIG = OUT / "figures"


def clean_host(endpoint_str):
    raw = str(endpoint_str).strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    return raw.split("/")[0].split(":")[0]


def load_effective_host_sets(policies_path=str(_P.data("data/policies_ci.jsonl"))):
    """Doc va loc nghiem ngat tap Tang 2 (Enforced, No-template, non-empty)."""
    p = Path(policies_path)
    if not p.exists():
        sys.exit(f"[!] Khong tim thay file {p}. Hay chay crawl/parse truoc.")

    groups = defaultdict(list)
    total_steps = 0
    with p.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)

            # Loc Tang 2
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            eps = r.get("endpoints") or r.get("hosts") or []
            if not eps:
                continue

            cleaned = frozenset(clean_host(e) for e in eps if clean_host(e))
            if cleaned:
                total_steps += 1
                groups[cleaned].append(r["repo"])

    return groups, total_steps


class FastDSU:
    """Disjoint Set Union de gom cum sieu toc."""
    def __init__(self, n):
        self.parent = list(range(n))
        self.size = [1] * n
        self.num_components = n

    def find(self, i):
        path = []
        while self.parent[i] != i:
            path.append(i)
            i = self.parent[i]
        for node in path:
            self.parent[node] = i
        return i

    def union(self, i, j):
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            if self.size[root_i] < self.size[root_j]:
                root_i, root_j = root_j, root_i
            self.parent[root_j] = root_i
            self.size[root_i] += self.size[root_j]
            self.num_components -= 1
            return True
        return False


def main():
    TBL.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("QUET TOAN BO DAI NGUONG JACCARD (0.01 -> 0.99)")
    print("=" * 70)

    groups, total_steps = load_effective_host_sets()
    keys = list(groups.keys())
    n_distinct = len(keys)
    n_repos = len({r for rs in groups.values() for r in rs})

    print(f"[*] Tong so Policy step xet       : {total_steps:,}")
    print(f"[*] Tong so Repository duy nhat    : {n_repos:,}")
    print(f"[*] Tong so Tap Host phan biet (N) : {n_distinct:,}")

    # 1. Xay dung Inverted Index de tim cac cap co do giao thoa > 0
    print("\n[*] Dang xay dung Inverted Index va tinh toan cac cap do tuong dong...")
    inv = defaultdict(set)
    for i, hs in enumerate(keys):
        for h in hs:
            inv[h].add(i)

    # Tinh tat ca cac cap (i, j) co Jaccard > 0
    pair_sims = []
    seen_pairs = set()

    for i, hs in enumerate(keys):
        candidates = set()
        for h in hs:
            candidates |= inv[h]
        for j in candidates:
            if j <= i:
                continue
            pair_key = (i, j)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            other = keys[j]
            inter = len(hs & other)
            if inter > 0:
                sim = inter / len(hs | other)
                pair_sims.append((sim, i, j))

    # Sap xep cac cap canh theo do tuong dong giam dan
    pair_sims.sort(key=lambda x: x[0], reverse=True)
    print(f"[*] Tim thay {len(pair_sims):,} cap co giao thoa > 0.")

    # 2. Quet Incremental tu 0.99 giam dan ve 0.01
    print("\n[*] Dang quet 99 nguong Jaccard tu 0.99 -> 0.01...")
    thresholds = [round(t * 0.01, 2) for t in range(99, 0, -1)]  # 0.99, 0.98, ..., 0.01

    dsu = FastDSU(n_distinct)
    edge_idx = 0
    n_edges = len(pair_sims)
    results = []

    for th in thresholds:
        # Them tat ca cac canh co do tuong dong >= th vao DSU hien tai
        while edge_idx < n_edges and pair_sims[edge_idx][0] >= th:
            _, u, v = pair_sims[edge_idx]
            dsu.union(u, v)
            edge_idx += 1

        # Thong ke phan bo cum hien tai
        comp_sizes = Counter(dsu.find(i) for i in range(n_distinct))
        n_clusters = dsu.num_components
        max_c_size = max(comp_sizes.values())
        singletons = sum(1 for sz in comp_sizes.values() if sz == 1)

        results.append({
            "threshold": th,
            "n_clusters": n_clusters,
            "max_cluster_size": max_c_size,
            "singletons": singletons,
            "compression_vs_steps": round(total_steps / n_clusters, 2),
            "compression_vs_distinct": round(n_distinct / n_clusters, 2),
        })

    # Dao nguoc lai de thu tu tu 0.01 -> 0.99
    results.reverse()
    df = pd.DataFrame(results)

    # 3. Luu file bang bieu
    csv_file = TBL / "t_jaccard_sweep.csv"
    df.to_csv(csv_file, index=False)
    print(f"\n>>> Da luu du lieu day du: {csv_file}")

    # Luu bang mau dep cho Paper (lay cac moc 0.1, 0.2, ... 0.8, 0.9, 0.99)
    sample_th = [0.01, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.99]
    sample_df = df[df["threshold"].isin(sample_th)].copy()
    
    (TBL / "t_jaccard_sweep.md").write_text(
        "**Bang phan tich do nhay gom cum Jaccard (0.01 -> 0.99)**\n\n" + 
        sample_df.to_markdown(index=False), encoding="utf-8"
    )
    (TBL / "t_jaccard_sweep.tex").write_text(
        sample_df.to_latex(index=False, caption="Jaccard Sensitivity Analysis (0.01 to 0.99)", label="tab:jaccard_sweep"),
        encoding="utf-8"
    )

    # In bang tom tat ra console
    print("\n" + "=" * 78)
    print(f"{'Nguong (T)':<12s} {'So Cum (N_eff)':<16s} {'Cum lon nhat':<16s} {'Cum don (Size=1)':<18s} {'Ghi chu'}")
    print("-" * 78)
    for _, row in sample_df.iterrows():
        th_val = row['threshold']
        note = ""
        if th_val == 0.8:
            note = "<- [Moc mac dinh trong Paper]"
        elif th_val == 0.01:
            note = "<- [Gom toi da]"
        elif th_val == 0.99:
            note = "<- [Gan nhu khong gop]"
        print(f"  {th_val:<10.2f} {int(row['n_clusters']):<16,d} {int(row['max_cluster_size']):<16,d} {int(row['singletons']):<18,d} {note}")
    print("=" * 78)

    # 4. Ve bieu do do nhay cho Paper
    if HAVE_PLT:
        fig, ax1 = plt.subplots(figsize=(6.0, 3.8))

        color1 = "#2b6cb0"
        ax1.set_xlabel("Nguong tuong dong Jaccard (Threshold T)", fontsize=10)
        ax1.set_ylabel("So cum doc lap (N hieu dung / Effective N)", color=color1, fontsize=10)
        line1 = ax1.plot(df["threshold"], df["n_clusters"], color=color1, linewidth=2, label="So cum (N_eff)")
        ax1.tick_params(axis="y", labelcolor=color1)
        ax1.set_xlim(0.0, 1.0)
        ax1.set_ylim(0, n_distinct * 1.05)

        # Danh dau diem dac biet T = 0.8
        val_08 = int(df[df["threshold"] == 0.8]["n_clusters"].values[0])
        ax1.axvline(x=0.8, color="#e53e3e", linestyle="--", alpha=0.8, linewidth=1.2)
        ax1.axhline(y=val_08, color="#e53e3e", linestyle=":", alpha=0.5, linewidth=1.0)
        ax1.plot(0.8, val_08, marker="o", color="#e53e3e", markersize=6)
        ax1.text(0.81, val_08 + 50, f"T = 0.80\nN_eff = {val_08:,}", color="#c53030", fontsize=9, fontweight="bold")

        # Duong tham chieu N_repos va N_distinct
        ax1.axhline(y=n_repos, color="#718096", linestyle="-.", alpha=0.5, linewidth=0.9)
        ax1.text(0.02, n_repos + 25, f"So Repo goc (N = {n_repos:,})", color="#4a5568", fontsize=7.5)

        ax1.axhline(y=n_distinct, color="#718096", linestyle="-.", alpha=0.5, linewidth=0.9)
        ax1.text(0.02, n_distinct - 70, f"Tap host phan biet (N = {n_distinct:,})", color="#4a5568", fontsize=7.5)

        plt.title("Duong cong do nhay gom cum Jaccard tren tap Egress Allowlist", fontsize=10.5, pad=12)
        plt.grid(True, linestyle="--", alpha=0.3)

        fig_path = FIG / "f_jaccard_sweep.png"
        plt.savefig(fig_path, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"\n>>> Da sinh bieu do do nhay chuan Paper: {fig_path}")


if __name__ == "__main__":
    main()