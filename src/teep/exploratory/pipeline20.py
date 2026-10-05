#!/usr/bin/env python3
"""
pipeline20.py - Chay pipeline S1 -> S2 tren 20 policy mau, xuat 4 nhom domain.

    S1  static analysis (measurement/static_rules.json)  -> D_static
    S2  bang tham chieu (measurement/s2_reference.json)  -> danh dau nghi ngo
    S3  quan sat traffic that                            -> CHUA CO (lam sau)

BON NHOM DOMAIN (tren tap hop D_static  U  D_declared):

    confirmed     co ca trong S1 va allowlist that   -> gan chac chan can
    static_only   S1 doan can, allowlist KHONG co    -> luat sai HOAC policy thieu
    declared_only allowlist co, S1 khong doan        -> ung vien over-privilege
                                                        (day la nhom chinh cua paper)

Moi domain trong allowlist con duoc S2 gan co: wildcard / open_namespace /
lots / doh_resolver / shared_ip.

CHAY
    python measurement/pipeline20.py
"""
from teep import paths as _P
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

DATA = _P.data("data")


def host_matches(pred, hosts):
    pred = pred.lower()
    if pred.startswith("*."):
        suf = pred[1:]
        return any(h == pred or h.endswith(suf) for h in hosts)
    return pred in hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=str(_P.data("measurement/sample20.json")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/pipeline_20.json")))
    ap.add_argument("--figdir", default=str(_P.data("analysis/figures")))
    a = ap.parse_args()

    sample = json.loads(Path(a.sample).read_text(encoding="utf-8"))["policies"]
    rules = json.loads(Path(a.rules).read_text(encoding="utf-8"))["rules"]
    for r in rules:
        r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]
    s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]

    results = []
    for p in sample:
        txt = (DATA / "files" / p["blob"]).read_text(encoding="utf-8", errors="replace")

        # ---- S1: static analysis ----
        d_static, provenance = set(), defaultdict(list)
        matched_rules = []
        for r in rules:
            if not any(rx.search(txt) for rx in r["_re"]):
                continue
            matched_rules.append(r["id"])
            for d in r["domains"]:
                d_static.add(d.lower())
                provenance[d.lower()].append(r["id"])

        declared = set(p["hosts"])

        # ---- doi chieu S1 vs allowlist that ----
        confirmed = {d for d in d_static if host_matches(d, declared)}
        static_only = d_static - confirmed
        declared_only = {h for h in declared
                         if not any(host_matches(d, {h}) for d in d_static)}

        # ---- S2: danh dau tung domain trong allowlist ----
        flags = {}
        for h in declared:
            info = s2.get(h)
            flags[h] = info["flags"] if info else []
        flag_count = Counter(f for fl in flags.values() for f in fl)
        suspicious = sorted(h for h, fl in flags.items()
                            if set(fl) - {"wildcard"})

        results.append({
            "sample_id": p["sample_id"], "repo": p["repo"], "path": p["path"],
            "job": p["job"], "stars": p["stars"], "ecosystems": p["ecosystems"],
            "n_declared": len(declared),
            "n_static": len(d_static),
            "matched_rules": matched_rules,
            "confirmed": sorted(confirmed),
            "static_only": sorted(static_only),
            "declared_only": sorted(declared_only),
            "n_confirmed": len(confirmed),
            "n_static_only": len(static_only),
            "n_declared_only": len(declared_only),
            "flags": flags,
            "flag_count": dict(flag_count),
            "suspicious_declared": suspicious,
            "domain_provenance": {k: v for k, v in provenance.items()},
        })

    Path(a.out).write_text(json.dumps({"n": len(results), "policies": results},
                                      indent=1, ensure_ascii=False), encoding="utf-8")

    # ---------------- bang ----------------
    print("=" * 100)
    print("PIPELINE S1 -> S2 TREN 20 POLICY MAU")
    print("=" * 100)
    print(f"{'id':4s} {'repo':32s} {'|I|':>4s} {'|S1|':>5s} {'conf':>5s} "
          f"{'S1-only':>8s} {'decl-only':>10s} {'nghi ngo':>9s}")
    print("-" * 100)
    for r in results:
        print(f"{r['sample_id']:4s} {r['repo'][:32]:32s} {r['n_declared']:4d} "
              f"{r['n_static']:5d} {r['n_confirmed']:5d} {r['n_static_only']:8d} "
              f"{r['n_declared_only']:10d} {len(r['suspicious_declared']):9d}")

    tot_decl = sum(r["n_declared"] for r in results)
    tot_conf = sum(r["n_confirmed"] for r in results)
    tot_do = sum(r["n_declared_only"] for r in results)
    tot_so = sum(r["n_static_only"] for r in results)
    tot_susp = sum(len(r["suspicious_declared"]) for r in results)
    print("-" * 100)
    print(f"{'TONG':4s} {'':32s} {tot_decl:4d} {'':5s} {tot_conf:5d} "
          f"{tot_so:8d} {tot_do:10d} {tot_susp:9d}")

    print("\n" + "=" * 100)
    print("CON SO CHINH")
    print("=" * 100)
    print(f"  Tong domain khai bao (20 policy)     : {tot_decl}")
    print(f"  S1 xac nhan (confirmed)              : {tot_conf}  ({100*tot_conf/tot_decl:.1f}%)")
    print(f"  Chi trong allowlist (declared-only)  : {tot_do}  ({100*tot_do/tot_decl:.1f}%)"
          f"   <- ung vien over-privilege")
    print(f"  Chi S1 doan (static-only)            : {tot_so}"
          f"   <- luat sai hoac policy thieu endpoint")
    print(f"  Domain bi S2 danh dau nghi ngo       : {tot_susp}  ({100*tot_susp/tot_decl:.1f}%)")

    allflags = Counter()
    for r in results:
        for f, c in r["flag_count"].items():
            allflags[f] += c
    print("\n  Co S2 tren toan bo domain khai bao:")
    for f, c in allflags.most_common():
        print(f"    {f:16s} {c:5d}  ({100*c/tot_decl:5.1f}%)")

    # ---------------- figure ----------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n[!] khong co matplotlib, bo qua figure")
        return

    fig_dir = Path(a.figdir)
    fig_dir.mkdir(parents=True, exist_ok=True)
    ids = [r["sample_id"] for r in results]

    # Fig 1: ba nhom chong nhau
    fig, ax = plt.subplots(figsize=(11, 5))
    c1 = [r["n_confirmed"] for r in results]
    c2 = [r["n_declared_only"] for r in results]
    c3 = [r["n_static_only"] for r in results]
    ax.bar(ids, c1, label="confirmed (S1 + allowlist)", color="#2a9d8f")
    ax.bar(ids, c2, bottom=c1, label="declared-only (ung vien over-privilege)", color="#e76f51")
    ax.bar(ids, c3, bottom=[i + j for i, j in zip(c1, c2)],
           label="static-only (S1 doan, khong khai)", color="#adb5bd")
    ax.set_ylabel("so domain")
    ax.set_title("Phan ra domain theo ba nhom, 20 policy mau")
    ax.legend(fontsize=8)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(fig_dir / "pipeline20_groups.png", dpi=150)
    plt.close()

    # Fig 2: co S2
    fig, ax = plt.subplots(figsize=(7, 4))
    if allflags:
        ks, vs = zip(*allflags.most_common())
        ax.barh(list(ks)[::-1], list(vs)[::-1], color="#264653")
        for i, v in enumerate(list(vs)[::-1]):
            ax.text(v + 1, i, str(v), va="center", fontsize=9)
    ax.set_xlabel("so domain khai bao bi gan co")
    ax.set_title("S2: co danh dau tren domain khai bao (20 policy)")
    plt.tight_layout()
    plt.savefig(fig_dir / "pipeline20_s2_flags.png", dpi=150)
    plt.close()

    # Fig 3: truoc/sau neu siet ve confirmed
    fig, ax = plt.subplots(figsize=(11, 4.5))
    x = range(len(ids))
    ax.bar([i - 0.2 for i in x], [r["n_declared"] for r in results], 0.4,
           label="allowlist hien tai |I|", color="#e76f51")
    ax.bar([i + 0.2 for i in x], c1, 0.4,
           label="neu siet ve confirmed", color="#2a9d8f")
    ax.set_xticks(list(x))
    ax.set_xticklabels(ids, rotation=45, ha="right")
    ax.set_ylabel("so domain")
    ax.set_yscale("log")
    ax.set_title("Kich thuoc allowlist truoc / sau khi siet (thang log)")
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(fig_dir / "pipeline20_before_after.png", dpi=150)
    plt.close()

    print(f"\n>>> {a.out}")
    for f in ("pipeline20_groups.png", "pipeline20_s2_flags.png",
              "pipeline20_before_after.png"):
        print(f">>> {fig_dir/f}")


if __name__ == "__main__":
    main()
