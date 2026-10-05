#!/usr/bin/env python3
r"""
compute_selection_bias.py - Chan selection bias cho would-break 98.4% (C6/C-a).

CAU HOI PEER-REVIEW: n=545 (repo co runtime evidence dang tin, dung cho coverage
test) la SELF-SELECTED - repo phat log DNS lay duoc thi thuong build phuc tap/
active hon -> co the THOI PHONG break rate. Vi 98.4% duoc dung nhu CAN DUOI cho
"static tightening khong deploy duoc", skew nay CUNG CHIEU (chi lam manh, khong
tao) ket luan - nhung phai DINH LUONG do skew, khong khang dinh suong.

Do do: so sanh do phuc tap cua subset 545 vs toan corpus, bang 2 proxy:
  (1) so host KHAI BAO / policy   (|I|, tu load_policies)   - full vs subset
  (2) so host KHAI BAO / repo     (tong |I| cac policy cua repo)
  (3) so workload domain R_exec / repo (chi co cho subset) - proxy truc tiep nhat
      cho "build cham nhieu dich"
In median/mean/quartile de bao cao 1 cau trong paper.

INPUT
    measurement/would_break_result.json   (rows: repo, n_rexec_workload, n_policy...)
    data/policies_ci.jsonl                 (load_policies -> n_hosts moi policy)
OUTPUT
    measurement/selection_bias_result.json
CHAY
    uv run python measurement/compute_selection_bias.py
"""
from teep import paths as _P
import argparse
import json
import statistics as st
from collections import defaultdict
from pathlib import Path

from teep.capacity.compute_residual_capacity import load_policies


def quantiles(xs):
    xs = sorted(xs)
    if not xs:
        return None
    n = len(xs)
    def q(p):
        i = max(0, min(n - 1, int(round(p * (n - 1)))))
        return xs[i]
    return {
        "n": n, "min": xs[0], "q1": q(0.25), "median": st.median(xs),
        "mean": round(st.mean(xs), 2), "q3": q(0.75), "max": xs[-1],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wb", default=str(_P.data("measurement/would_break_result.json")))
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--out", default=str(_P.data("measurement/selection_bias_result.json")))
    a = ap.parse_args()

    wb = json.loads(Path(a.wb).read_text(encoding="utf-8"))
    subset_repos = {r["repo"] for r in wb["rows"]}
    rexec_per_repo = {r["repo"]: r["n_rexec_workload"] for r in wb["rows"]}
    print(f"[*] subset (would-break eligible) = {len(subset_repos)} repo")

    policies = load_policies(a.policies)
    # per-policy declared-host count
    declared_all = [p["n_hosts"] for p in policies]
    declared_subset = [p["n_hosts"] for p in policies if p["repo"] in subset_repos]
    # per-repo declared-host total
    repo_hosts = defaultdict(int)
    repo_npol = defaultdict(int)
    for p in policies:
        repo_hosts[p["repo"]] += p["n_hosts"]
        repo_npol[p["repo"]] += 1
    repo_hosts_all = list(repo_hosts.values())
    repo_hosts_subset = [repo_hosts[r] for r in subset_repos if r in repo_hosts]
    repo_npol_all = list(repo_npol.values())
    repo_npol_subset = [repo_npol[r] for r in subset_repos if r in repo_npol]
    rexec_vals = list(rexec_per_repo.values())

    res = {
        "declared_hosts_per_policy": {
            "full_corpus": quantiles(declared_all),
            "would_break_subset": quantiles(declared_subset),
        },
        "declared_hosts_per_repo": {
            "full_corpus": quantiles(repo_hosts_all),
            "would_break_subset": quantiles(repo_hosts_subset),
        },
        "policies_per_repo": {
            "full_corpus": quantiles(repo_npol_all),
            "would_break_subset": quantiles(repo_npol_subset),
        },
        "rexec_workload_per_repo_subset_only": quantiles(rexec_vals),
    }

    print("=" * 74)
    print("SELECTION BIAS: subset 545 vs full corpus")
    print("=" * 74)
    for metric, blk in res.items():
        print(f"\n{metric}:")
        if metric.endswith("subset_only"):
            print(f"    subset: {blk}")
            continue
        f, s = blk["full_corpus"], blk["would_break_subset"]
        print(f"    full  : median={f['median']}  mean={f['mean']}  q1={f['q1']} q3={f['q3']} (n={f['n']})")
        print(f"    subset: median={s['median']}  mean={s['mean']}  q1={s['q1']} q3={s['q3']} (n={s['n']})")

    # cau goi y cho paper
    dm_f = res["declared_hosts_per_repo"]["full_corpus"]["median"]
    dm_s = res["declared_hosts_per_repo"]["would_break_subset"]["median"]
    print("\n" + "-" * 74)
    print("CAU GOI Y (dieu chinh theo so thuc te in ra):")
    print(f'  "The 545 repositories declare a median of {dm_s} destinations each,')
    print(f'   against {dm_f} across the corpus; the coverage-test subset is thus')
    print(f'   somewhat more complex than average, which reinforces rather than')
    print(f'   creates the high break rate, and 98.4% remains a lower bound."')
    print("  (Neu median subset <= full: skew NGUOC - phai viet lai, bao Bao.)")

    Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
