#!/usr/bin/env python3
"""
    - |I|: So domain khai bao trong allowlist (Declared)
    - |E|: Tong so domain thuc te co the tiep can (do dung chung IP tren CDN / Tranco)
    - Amplification (|E| / |I|): Be mat tan cong bi phong dai bao nhieu lan?
    - analysis/figures/amplification_histogram.png (Histogram phan bo he so khuech dai)
    - analysis/figures/class_abc_distribution.png (Bar chart phan bo Lop A / Lop B / Clean)
"""
from teep import paths as _P
import json
from collections import Counter
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    raise SystemExit("Thieu matplotlib/numpy. Chay: pip install matplotlib numpy")

SAMPLE_PATH = Path(str(_P.data("measurement/sample20.json")))
S2_PATH = Path(str(_P.data("measurement/s2_reference.json")))
OUT_JSON = Path(str(_P.data("measurement/amplification_20.json")))
FIG_DIR = Path(str(_P.data("analysis/figures")))


def main():
    if not SAMPLE_PATH.exists() or not S2_PATH.exists():
        raise SystemExit("Khong tim thay sample20.json hoac s2_reference.json!")

    samples = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))["policies"]
    s2_hosts = json.loads(S2_PATH.read_text(encoding="utf-8"))["hosts"]

    FIG_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    for p in samples:
        pid = p["sample_id"]
        repo = p["repo"]
        declared_hosts = p["hosts"]
        n_I = len(declared_hosts)  # |I|

        # Tap tat ca cac domain thuc te co the tiep can qua IP chung (Co-tenancy)
        reachable_domains = set(declared_hosts)
        class_counts = {"A": 0, "B": 0, "Clean": 0}

        for h in declared_hosts:
            info = s2_hosts.get(h)
            if info:
                # Gom cac domain Tranco dung chung IP
                reachable_domains.update(info.get("cotenant_sample", []))
                # Neu co n_cotenants lon hon sample thi tinh tong the
                cls = info.get("psl_class", "?")
                if "open_namespace" in info.get("flags", []) or cls == "A":
                    class_counts["A"] += 1
                elif cls == "B" or "wildcard" in info.get("flags", []):
                    class_counts["B"] += 1
                else:
                    class_counts["Clean"] += 1
            else:
                class_counts["Clean"] += 1

        # |E| = Tong tap hop cac domain tiep can duoc
        n_E = len(reachable_domains)
        amplification = round(n_E / max(n_I, 1), 2)

        results.append({
            "sample_id": pid,
            "repo": repo,
            "stars": p["stars"],
            "n_I": n_I,
            "n_E": n_E,
            "amplification": amplification,
            "class_A": class_counts["A"],
            "class_B": class_counts["B"],
            "class_Clean": class_counts["Clean"],
        })

    # Ghi file JSON ket qua Mục 3
    OUT_JSON.write_text(json.dumps({"n": len(results), "policies": results}, indent=2, ensure_ascii=False), encoding="utf-8")

    # =========================================================================
    # IN BANG KET QUA MUC 3 (20 CON SO)
    # =========================================================================
    print("=" * 86)
    print(f"{'ID':4s} {'Repository':36s} {'|I|':>5s} {'|E|':>6s} {'Amplification (|E|/|I|)':>24s} {'Lớp A/B/Clean':>14s}")
    print("-" * 86)
    amp_list = []
    for r in results:
        amp_list.append(r["amplification"])
        classes_str = f"{r['class_A']}/{r['class_B']}/{r['class_Clean']}"
        print(f"{r['sample_id']:4s} {r['repo'][:36]:36s} {r['n_I']:5d} {r['n_E']:6d} {r['amplification']:20.2f}x {classes_str:>14s}")
    print("-" * 86)
    print(f"[*] Trung vi (Median) Amplification : {np.median(amp_list):.2f}x")
    print(f"[*] Trung binh (Mean) Amplification : {np.mean(amp_list):.2f}x")
    print(f"[*] Max Amplification              : {max(amp_list):.2f}x")
    print(f">>> Da luu ket qua: {OUT_JSON}")

    # =========================================================================
    # MUC 5 - HINH 1: HISTOGRAM AMPLIFICATION FACTOR
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    ax.hist(amp_list, bins=10, color="#2a9d8f", edgecolor="#264653", alpha=0.85, rwidth=0.88)
    ax.axvline(np.median(amp_list), color="#e76f51", linestyle="--", linewidth=2,
               label=f"Median = {np.median(amp_list):.2f}x")
    ax.axvline(np.mean(amp_list), color="#e63946", linestyle=":", linewidth=2,
               label=f"Mean = {np.mean(amp_list):.2f}x")
    ax.set_xlabel("Hệ số khuếch đại bề mặt tấn công (|E| / |I|)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Số lượng Policy", fontsize=11, fontweight="bold")
    ax.set_title("Phân bố Hệ số Khuếch đại Bề mặt Egress (|E| / |I|) trên 20 Policy Mẫu", fontsize=12, pad=12)
    ax.legend(fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig1_path = FIG_DIR / "amplification_histogram.png"
    plt.savefig(fig1_path)
    plt.close()
    print(f"\n[+] Da tao Bieu do 1: {fig1_path}")

    # =========================================================================
    # MUC 5 - HINH 2: BAR CHART PHAN BO LOP A / LOP B / CLEAN
    # =========================================================================
    fig, ax = plt.subplots(figsize=(11, 5), dpi=300)
    ids = [r["sample_id"] for r in results]
    cA = [r["class_A"] for r in results]
    cB = [r["class_B"] for r in results]
    cClean = [r["class_Clean"] for r in results]

    x = np.arange(len(ids))
    ax.bar(x, cClean, label="Clean / Lớp C (Single-tenant / Private)", color="#2a9d8f")
    ax.bar(x, cB, bottom=cClean, label="Lớp B (Vendor eTLD+1 / Single-org)", color="#e9c46a")
    ax.bar(x, cA, bottom=[i + j for i, j in zip(cClean, cB)],
           label="Lớp A (Open Multi-tenant Namespace - Rủi ro cao)", color="#e76f51")

    ax.set_xticks(x)
    ax.set_xticklabels(ids, rotation=45, ha="right", fontsize=9)
    ax.set_xlabel("Policy Mẫu (Sample ID)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Số lượng Host", fontsize=11, fontweight="bold")
    ax.set_title("Phân loại Rủi ro Domain theo Lớp A / Lớp B / Clean (20 Policy Mẫu)", fontsize=12, pad=12)
    ax.legend(fontsize=9, loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig2_path = FIG_DIR / "class_abc_distribution.png"
    plt.savefig(fig2_path)
    plt.close()
    print(f"[+] Da tao Bieu do 2: {fig2_path}")


if __name__ == "__main__":
    main()