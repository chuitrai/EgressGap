#!/usr/bin/env python3
"""
evaluate_policy.py - Do metric cho allowlist truoc/sau khi siet.

DINH NGHIA (thong nhat toan bai):
    I   = allowlist khai bao (declared)
    S1  = precision policy tu phan tich tinh (domain workload duoc du doan can)
    S2  = ANNOTATE moi host: psl_class, lots, so co-tenant (share IP), wildcard
          -> S2 khong quyet dinh giu/bo, chi cap thuoc tinh de tinh metric
    S3  = domain quan sat that tu capture traffic (neu co file r_*.json)

METRIC MOI POLICY:
    |I|                         kich thuoc khai bao
    |S1|                        kich thuoc precision policy
    justified   = |I ∩ S1(∪S3)| host co bang chung can
    unjustified = |I \ (S1∪S3)| host chi co trong khai bao  -> over-declaration
    over_decl_ratio = unjustified / |I|

    RESIDUAL REACH (nang luc ro ri con lai):
      reach(P) = P  ∪  { domain khac cung IP voi bat ky host trong P }
                 (co-tenant lay tu Tranco top-100k -> CAN DUOI)
      expansion(P) = |reach(P)| / |P|
      -> so sanh reach(I) truoc va reach(I') sau khi siet

CHAY
    python measurement/evaluate_policy.py                       # 20 policy mau
    python measurement/evaluate_policy.py --sample <file.json>  # bo policy khac
"""
from teep import paths as _P
import argparse
import collections
import json
import statistics as st
from pathlib import Path

from teep.capacity.tighten_policy import compile_rules, static_domains, tighten, host_matches

DATA = _P.data("data")


def build_fanin(path=str(_P.data("tranco/resolved_top100000.jsonl"))):
    ip2dom = collections.defaultdict(set)
    p = Path(path)
    if not p.exists():
        return ip2dom
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            for ip in r.get("ips") or []:
                ip2dom[ip].add(r["d"])
    return ip2dom


def reach(hosts, resolved, ip2dom):
    """Tap domain THUC TE cham toi duoc qua co-tenancy shared-IP."""
    out = set(h.lower() for h in hosts)
    for h in hosts:
        for ip in resolved.get(h.lower(), []):
            out |= ip2dom.get(ip, set())
    return out


def load_s3(hosts_dir="."):
    """Gom moi r_*.json thanh {label: set(host)}. Rong neu chua capture."""
    s3 = {}
    for fp in Path(hosts_dir).glob("r_*.json"):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
            s3[fp.stem] = set(h.lower() for h in d.get("required_set", []))
        except Exception:
            pass
    return s3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=str(_P.data("measurement/sample20.json")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    ap.add_argument("--resolved", default=str(_P.data("cotenancy/resolved.json")))
    ap.add_argument("--tranco", default=str(_P.data("tranco/resolved_top100000.jsonl")))
    ap.add_argument("--out", default=str(_P.data("measurement/policy_metrics.json")))
    ap.add_argument("--figdir", default=str(_P.data("analysis/figures")))
    a = ap.parse_args()

    sample = json.loads(Path(a.sample).read_text(encoding="utf-8"))["policies"]
    rules = compile_rules(a.rules)
    s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]
    resolved = json.loads(Path(a.resolved).read_text(encoding="utf-8"))
    ip2dom = build_fanin(a.tranco)
    s3_all = load_s3(".")
    print(f"[*] {len(sample)} policy | S2 {len(s2)} host | resolved {len(resolved)} "
          f"| fan-in {len(ip2dom):,} IP | S3 files: {len(s3_all)}")

    rows = []
    for p in sample:
        txt = (DATA / "files" / p["blob"]).read_text(encoding="utf-8", errors="replace")
        declared = [h.lower() for h in p["hosts"]]
        s1, prov, matched = static_domains(txt, rules)

        # S3: dung neu co file r_*.json khop label; o day chua map tung policy
        # nen de trong (khung san sang cam vao)
        s3_hosts = set()

        justified = [h for h in declared
                     if any(host_matches(d, h) for d in s1) or h in s3_hosts]
        unjustified = [h for h in declared if h not in justified]

        kept, dropped, reason = tighten(declared, s1, s3_hosts)

        reach_before = reach(declared, resolved, ip2dom)
        reach_after = reach(kept, resolved, ip2dom)

        # S2 annotate tren host khai bao
        flags = collections.Counter()
        for h in declared:
            info = s2.get(h)
            if info:
                for fl in info["flags"]:
                    flags[fl] += 1

        rows.append({
            "id": p["sample_id"], "repo": p["repo"], "stars": p["stars"],
            "ecosystems": p["ecosystems"],
            "n_declared": len(declared),
            "n_s1": len(s1),
            "n_justified": len(justified),
            "n_unjustified": len(unjustified),
            "over_decl_ratio": round(len(unjustified) / len(declared), 3) if declared else 0,
            "n_kept": len(kept), "n_dropped": len(dropped),
            "reach_before": len(reach_before),
            "reach_after": len(reach_after),
            "expansion_before": round(len(reach_before) / len(declared), 2) if declared else 0,
            "expansion_after": round(len(reach_after) / len(kept), 2) if kept else 0,
            "s2_flags": dict(flags),
            "dropped_hosts": dropped,
            "matched_rules": matched,
        })

    Path(a.out).write_text(json.dumps({"n": len(rows), "policies": rows},
                                      indent=1, ensure_ascii=False), encoding="utf-8")

    # -------------------- BANG --------------------
    print("\n" + "=" * 104)
    print("METRIC MOI POLICY (truoc / sau khi siet)")
    print("=" * 104)
    ikept = "|I'|"
    print(f"{'id':4s} {'repo':28s} {'|I|':>4s} {'|S1|':>4s} {'just':>4s} "
          f"{'unjust':>6s} {'%OD':>5s} {ikept:>5s} {'reach_b':>7s} {'reach_a':>7s} {'giam%':>6s}")
    print("-" * 104)
    for r in rows:
        red = 100 * (r["reach_before"] - r["reach_after"]) / r["reach_before"] if r["reach_before"] else 0
        print(f"{r['id']:4s} {r['repo'][:28]:28s} {r['n_declared']:4d} {r['n_s1']:4d} "
              f"{r['n_justified']:4d} {r['n_unjustified']:6d} {r['over_decl_ratio']*100:4.0f}% "
              f"{r['n_kept']:5d} {r['reach_before']:7d} {r['reach_after']:7d} {red:5.0f}%")

    # -------------------- TONG --------------------
    decl = [r["n_declared"] for r in rows]
    od = [r["over_decl_ratio"] for r in rows]
    rb = [r["reach_before"] for r in rows]
    ra = [r["reach_after"] for r in rows]
    kept = [r["n_kept"] for r in rows]
    reductions = [100 * (r["reach_before"] - r["reach_after"]) / r["reach_before"]
                  for r in rows if r["reach_before"]]

    print("\n" + "=" * 104)
    print("CON SO TONG HOP")
    print("=" * 104)
    print(f"  |I| khai bao          : median {st.median(decl):.1f}  mean {st.mean(decl):.1f}  max {max(decl)}")
    print(f"  |I'| sau siet         : median {st.median(kept):.1f}  mean {st.mean(kept):.1f}  max {max(kept)}")
    print(f"  Over-declaration ratio: median {st.median(od)*100:.0f}%  mean {st.mean(od)*100:.0f}%")
    print(f"  Reach truoc siet      : median {st.median(rb):.0f}  max {max(rb)}")
    print(f"  Reach sau siet        : median {st.median(ra):.0f}  max {max(ra)}")
    print(f"  Giam reach (residual) : median {st.median(reductions):.0f}%  "
          f"min {min(reductions):.0f}%  max {max(reductions):.0f}%")

    allflags = collections.Counter()
    for r in rows:
        for f, c in r["s2_flags"].items():
            allflags[f] += c
    tot = sum(decl)
    print(f"\n  S2 annotate tren {tot} host khai bao:")
    for f, c in allflags.most_common():
        print(f"    {f:16s} {c:4d}  ({100*c/tot:4.1f}%)")

    # -------------------- FIGURE --------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n[!] khong co matplotlib")
        return
    fd = Path(a.figdir); fd.mkdir(parents=True, exist_ok=True)
    ids = [r["id"] for r in rows]

    # Fig A: reach truoc/sau (thang log)
    fig, ax = plt.subplots(figsize=(11, 4.5))
    x = range(len(ids))
    ax.bar([i - 0.2 for i in x], rb, 0.4, label="reach truoc siet", color="#e76f51")
    ax.bar([i + 0.2 for i in x], ra, 0.4, label="reach sau siet", color="#2a9d8f")
    ax.set_yscale("log"); ax.set_xticks(list(x))
    ax.set_xticklabels(ids, rotation=45, ha="right")
    ax.set_ylabel("residual reach (so domain, log)")
    ax.set_title("Nang luc ro ri con lai: truoc vs sau khi siet policy")
    ax.legend(fontsize=8); plt.tight_layout()
    plt.savefig(fd / "eval_reach_before_after.png", dpi=150); plt.close()

    # Fig B: over-declaration ratio sap xep
    fig, ax = plt.subplots(figsize=(11, 4))
    sr = sorted(rows, key=lambda r: -r["over_decl_ratio"])
    ax.bar([r["id"] for r in sr], [r["over_decl_ratio"]*100 for r in sr], color="#264653")
    ax.axhline(st.median(od)*100, ls="--", color="grey",
               label=f"median {st.median(od)*100:.0f}%")
    ax.set_ylabel("% host khong co bang chung (over-declaration)")
    ax.set_title("Ty le over-declaration moi policy (giam dan)")
    ax.legend(); plt.xticks(rotation=45, ha="right"); plt.tight_layout()
    plt.savefig(fd / "eval_over_declaration.png", dpi=150); plt.close()

    print(f"\n>>> {a.out}")
    print(f">>> {fd/'eval_reach_before_after.png'}")
    print(f">>> {fd/'eval_over_declaration.png'}")


if __name__ == "__main__":
    main()
