#!/usr/bin/env python3
"""
demo_pipeline.py - Chay thu toan bo chuoi cho GitHub Actions egress.

CHUOI:  R (do tu traffic)  ->  E (tinh tu policy)  ->  Coverage / Tightness
                                                   ->  Set-cover sinh allowlist toi thieu

Muc dich: chung minh ca ba khau (do, danh gia, sinh) chay duoc voi du lieu that,
truoc khi dau tu ca tuan.

CHAY
    python demo_pipeline.py                  # dung du lieu mau kem san
    python demo_pipeline.py --r r_pip.json   # dung R do duoc tu oracle_proxy.py
"""

import argparse
import json
from itertools import combinations
from pathlib import Path

# ---------------------------------------------------------------- du lieu vao
# R: tap dich THUC SU CAN, do bang oracle_proxy.py (da chay that)
R_MEASURED = {
    "pip download six":  ["pypi.org", "files.pythonhosted.org"],
    "npm install":       ["registry.npmjs.org"],
    "checkout + pip":    ["github.com", "codeload.github.com",
                          "pypi.org", "files.pythonhosted.org"],
}

# I: allowlist THUC TE, lay tu corpus (mau dai dien, median 6 host)
I_REAL = [
    "github.com", "api.github.com", "objects.githubusercontent.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
]

# So domain khac dung chung dia chi, do tu dns_cotenancy (chan duoi noi bo corpus).
# Trong ban that: thay bang ket qua Tranco top-100k.
COTENANTS = {
    "github.com": 1, "api.github.com": 1, "codeload.github.com": 1,
    "objects.githubusercontent.com": 3,     # chung IP voi raw./pkg-containers./release-assets.
    "raw.githubusercontent.com": 3, "pkg-containers.githubusercontent.com": 3,
    "release-assets.githubusercontent.com": 3,
    "pypi.org": 7, "files.pythonhosted.org": 7,   # Fastly, dung chung
    "registry.npmjs.org": 11,                      # Cloudflare
    "index.docker.io": 14,
}

# So subdomain that su ton tai duoi mot wildcard (do qua CT log trong ban that)
WILDCARD_EXPANSION = {
    "*.githubusercontent.com": 40,
    "*.blob.core.windows.net": 10**6,      # namespace mo — ai cung dang ky duoc
    "*.github.com": 60,
}

# Cac subdomain mot wildcard bao phu (de set-cover biet ung vien nao phu duoc gi)
WILDCARD_COVERS = {
    "*.githubusercontent.com": {
        "objects.githubusercontent.com", "raw.githubusercontent.com",
        "pkg-containers.githubusercontent.com", "release-assets.githubusercontent.com",
    },
    "*.github.com": {"github.com", "api.github.com", "codeload.github.com"},
}


def expand(entry):
    """|expand(e)| — so dich mot entry thuc su mo ra."""
    if "*" in entry:
        return WILDCARD_EXPANSION.get(entry, 100)
    return 1 + COTENANTS.get(entry, 0)     # chinh no + co-tenant


def effective_size(entries):
    return sum(expand(e) for e in entries)


def covers(entry):
    if "*" in entry:
        return WILDCARD_COVERS.get(entry, set())
    return {entry}


# ---------------------------------------------------------------- set cover
def greedy_min_expansion(R, candidates):
    """Chon tap entry phu het R, cuc tieu hoa tong |expand|.
    Greedy: moi buoc chon entry co ti le chi-phi / so-phan-tu-moi thap nhat."""
    remaining, chosen = set(R), []
    while remaining:
        best, best_ratio = None, float("inf")
        for c in candidates:
            new = covers(c) & remaining
            if not new:
                continue
            ratio = expand(c) / len(new)
            if ratio < best_ratio:
                best, best_ratio = c, ratio
        if best is None:
            return chosen, remaining          # khong phu duoc het
        chosen.append(best)
        remaining -= covers(best)
    return chosen, set()


def exhaustive_min_expansion(R, candidates, max_k=6):
    """Loi giai toi uu bang vet can — chi dung de kiem tra greedy tren R nho."""
    best, best_size = None, float("inf")
    for k in range(1, min(max_k, len(candidates)) + 1):
        for combo in combinations(candidates, k):
            cov = set()
            for c in combo:
                cov |= covers(c)
            if set(R) <= cov:
                s = effective_size(combo)
                if s < best_size:
                    best, best_size = list(combo), s
    return best, best_size


# ---------------------------------------------------------------- bao cao
def evaluate(label, R, I):
    E_hosts, E_size = set(), 0
    for e in I:
        E_hosts |= covers(e)
        E_size += expand(e)
    cov = len(set(R) & E_hosts) / len(R) if R else 0
    tight = len(R) / E_size if E_size else 0
    print(f"\n  {label}")
    print(f"    |R| = {len(R):3d}   {sorted(R)}")
    print(f"    |I| = {len(I):3d}   entry duoc viet ra")
    print(f"    |E| = {E_size:3d}   dich thuc su toi duoc")
    print(f"    Coverage  = {cov:.2f}   {'OK' if cov == 1 else '!! BUILD HONG'}")
    print(f"    Tightness = {tight:.3f}  (cang gan 1 cang chat)")
    print(f"    Amplification |E|/|I| = {E_size/len(I):.1f}x")
    return E_size, cov, tight


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r", help="file JSON tu oracle_proxy.py")
    a = ap.parse_args()

    print("=" * 72)
    print("BUOC 1 — R: tap dich THUC SU CAN (do bang oracle_proxy.py)")
    print("=" * 72)
    if a.r and Path(a.r).exists():
        d = json.loads(Path(a.r).read_text())
        R_MEASURED[d.get("label", "measured")] = d["required_set"]
    for k, v in R_MEASURED.items():
        print(f"  {k:22s} -> {len(v)} host  {v}")

    print()
    print("=" * 72)
    print("BUOC 2 — DANH GIA policy that trong corpus")
    print("=" * 72)
    R = R_MEASURED["checkout + pip"]
    evaluate("Allowlist THUC TE trong corpus (median 6 host)", R, I_REAL)

    print()
    print("=" * 72)
    print("BUOC 3 — SO SANH 3 CACH SINH POLICY")
    print("=" * 72)

    # (a) Baseline nha cung cap: liet ke dung nhung gi quan sat duoc
    vendor = list(R)
    e_vendor, _, _ = evaluate("(a) Vendor recommender: liet ke dung R quan sat duoc", R, vendor)

    # (b) Cach nguoi ta hay viet: dung wildcard cho gon
    wildcarded = ["*.github.com", "pypi.org", "files.pythonhosted.org"]
    e_wild, cov_w, _ = evaluate("(b) Nguoi dung tu viet: gom bang wildcard cho gon", R, wildcarded)

    # (c) Cua minh: set-cover cuc tieu hoa E
    candidates = sorted(set(R) | set(WILDCARD_COVERS))
    chosen, left = greedy_min_expansion(R, candidates)
    e_ours, _, _ = evaluate("(c) Set-cover cuc tieu hoa |E| (phuong phap cua minh)", R, chosen)
    print(f"    entry chon: {chosen}")

    opt, opt_size = exhaustive_min_expansion(R, candidates)
    print(f"\n    Kiem tra greedy: toi uu vet can = {opt_size}, greedy = {e_ours} "
          f"({'TRUNG' if opt_size == e_ours else 'LECH ' + str(e_ours - opt_size)})")

    print()
    print("=" * 72)
    print("KET LUAN CHAY THU")
    print("=" * 72)
    print(f"  Vendor recommender      |E| = {e_vendor}")
    print(f"  Nguoi dung dung wildcard|E| = {e_wild}   ({e_wild/e_vendor:.1f}x vendor)")
    print(f"  Set-cover cua minh      |E| = {e_ours}   ({e_ours/e_vendor:.2f}x vendor)")
    print()
    print("  -> Ca ba deu Coverage = 1.0, tuc khong cai nao lam hong build.")
    print("  -> Khac nhau o |E|. Do la KHONG GIAN TOI UU HOA, va chua ai do.")
    print()
    print("  Luu y: cac con so COTENANTS o day la chan duoi noi bo corpus.")
    print("  Thay bang ket qua Tranco top-100k thi khoang cach se ro hon nhieu.")


if __name__ == "__main__":
    main()
