#!/usr/bin/env python3
r"""
compute_mcnemar.py - McNemar cho cap ti le 66.6% (before) vs 36.9% (after)
tightening, thay cho so sanh 2 Wilson CI doc lap (peer-review C7 / P1).

LY DO: 66.6% va 36.9% la QUAN SAT GHEP CAP tren CUNG 7137 policy (moi policy
co ca has_residual_before_strict va has_residual_after_strict). So sanh 2 CI
doc lap la SAI loai test. McNemar la test dung cho ti le ghep cap.

Doc thang measurement/tighten_full_corpus.json (da co san field ghep cap moi
policy) - KHONG tinh lai gi, chi dem bang 2x2:
    a = before T, after T   (van con residual sau tighten)
    b = before T, after F   (tighten GO BO residual)   <- discordant
    c = before F, after T   (tighten TAO residual)      <- discordant, ky vong ~0
    d = before F, after F   (von da sach)
McNemar (co hieu chinh lien tuc): chi2 = (|b-c|-1)^2 / (b+c), df=1.
p tinh bang ham song sot chi2_1 = erfc(sqrt(chi2/2)) - KHONG can scipy.
Neu b+c nho, in them p CHINH XAC (binomial hai phia).

CHAY
    uv run python measurement/compute_mcnemar.py
"""
from teep import paths as _P
import argparse
import json
import math
from pathlib import Path


def chi2_1_sf(x):
    """Survival function cua chi-square df=1 (khong can scipy)."""
    return math.erfc(math.sqrt(x / 2.0))


def exact_binom_two_sided(b, c):
    """p chinh xac McNemar: 2 * P(X <= min(b,c)) voi X~Binom(b+c, 0.5), cap 1.0."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    return min(1.0, 2.0 * tail)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(_P.data("measurement/tighten_full_corpus.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/mcnemar_result.json")))
    a = ap.parse_args()

    d = json.loads(Path(a.src).read_text(encoding="utf-8"))
    rows = d["rows"]

    a_cell = b_cell = c_cell = d_cell = 0
    for r in rows:
        before = r["has_residual_before_strict"]
        after = r["has_residual_after_strict"]
        if before and after:
            a_cell += 1
        elif before and not after:
            b_cell += 1
        elif not before and after:
            c_cell += 1
        else:
            d_cell += 1

    n = len(rows)
    disc = b_cell + c_cell
    if disc == 0:
        raise SystemExit("Khong co cap discordant - khong chay McNemar duoc.")
    chi2 = (abs(b_cell - c_cell) - 1) ** 2 / disc if disc > 0 else float("nan")
    p_chi2 = chi2_1_sf(chi2)
    p_exact = exact_binom_two_sided(b_cell, c_cell)

    # doi chieu sanity voi con so headline
    pct_before = 100 * (a_cell + b_cell) / n
    pct_after = 100 * (a_cell + c_cell) / n

    print("=" * 70)
    print("McNemar: residual (strict) truoc vs sau tightening, ghep cap / policy")
    print("=" * 70)
    print(f"  n policy = {n}")
    print(f"  Bang 2x2 (before x after):")
    print(f"    a (T,T) van residual        = {a_cell}")
    print(f"    b (T,F) tighten GO residual  = {b_cell}   <- discordant")
    print(f"    c (F,T) tighten TAO residual = {c_cell}   <- discordant (ky vong ~0)")
    print(f"    d (F,F) von sach            = {d_cell}")
    print(f"  [sanity] before = (a+b)/n = {pct_before:.2f}%  (phai ~66.58)")
    print(f"  [sanity] after  = (a+c)/n = {pct_after:.2f}%  (phai ~36.91)")
    print(f"  McNemar chi2 (continuity-corrected, df=1) = {chi2:.3f}")
    print(f"  p (chi2 approx) = {p_chi2:.3e}")
    print(f"  p (exact binomial, hai phia) = {p_exact:.3e}")
    verdict = "p < 0.001" if max(p_chi2, p_exact) < 1e-3 else f"p = {max(p_chi2, p_exact):.3g}"
    print(f"  -> Cau cho paper: McNemar's test, {verdict}.")

    Path(a.out).write_text(json.dumps({
        "n": n, "a_TT": a_cell, "b_TF": b_cell, "c_FT": c_cell, "d_FF": d_cell,
        "chi2_cc": round(chi2, 4), "p_chi2_approx": p_chi2, "p_exact": p_exact,
        "pct_before_check": round(pct_before, 2), "pct_after_check": round(pct_after, 2),
    }, indent=1), encoding="utf-8")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
