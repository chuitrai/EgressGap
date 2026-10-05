#!/usr/bin/env python3
"""
policy_scorecard.py - Metric cho MOT policy cu the (khong phai tong hop 20 cai).

Tra loi cau: "cho mot allowlist bat ky, cac con so danh gia no la gi?"

DAU VAO
    --declared : allowlist khai bao (I) - list host hoac file txt/json
    --observed : S3 = domain quan sat that (R) - list hoac file r_*.json
                 (neu khong co: chi tinh duoc metric khong can R)

METRIC (moi cai mot dong, giai thich duoc):
    |I|            so host khai bao
    |R|            so host that su can (tu S3)
    Coverage  = |R ∩ I| / |R|    -> allowlist co DU cho build khong (1.0 = du)
    Utilization = |R ∩ I| / |I|  -> bao nhieu % allowlist THUC SU dung
    Over-declaration = |I \\ R| / |I| = 1 - Utilization  -> % thua
    |E|            residual reach (domain cham toi duoc qua shared-IP)
    Expansion = |E| / |I|        -> mot dong allowlist mo ra bao nhieu dich
    Tightness = |R| / |E|        -> gan toi thieu the nao (1.0 = khong the chat hon)

CHAY
    python measurement/policy_scorecard.py \\
        --declared github.com,api.github.com,pypi.org,files.pythonhosted.org,registry.npmjs.org \\
        --observed github.com,pypi.org,files.pythonhosted.org
"""
from teep import paths as _P
import argparse
import collections
import json
from pathlib import Path


def load_hosts(arg):
    if not arg:
        return None
    p = Path(arg)
    if p.exists():
        if p.suffix == ".json":
            d = json.loads(p.read_text(encoding="utf-8"))
            return [h.lower().split(":")[0] for h in d.get("required_set", [])]
        return [l.strip().lower().split(":")[0] for l in p.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
    return [h.strip().lower().split(":")[0] for h in arg.split(",") if h.strip()]


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
    out = set(h.lower() for h in hosts)
    detail = {}
    for h in hosts:
        co = set()
        for ip in resolved.get(h.lower(), []):
            co |= ip2dom.get(ip, set())
        co.discard(h.lower())
        if co:
            detail[h] = sorted(co)
        out |= co
    return out, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--declared", required=True)
    ap.add_argument("--observed", default=None, help="S3 (R). Bo trong neu chua co.")
    ap.add_argument("--label", default="policy")
    ap.add_argument("--resolved", default=str(_P.data("cotenancy/resolved.json")))
    ap.add_argument("--tranco", default=str(_P.data("tranco/resolved_top100000.jsonl")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    a = ap.parse_args()

    I = list(dict.fromkeys(load_hosts(a.declared)))
    R = load_hosts(a.observed)
    resolved = json.loads(Path(a.resolved).read_text(encoding="utf-8"))
    ip2dom = build_fanin(a.tranco)
    s2 = {}
    if Path(a.s2).exists():
        s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]

    E, edetail = reach(I, resolved, ip2dom)

    print("=" * 70)
    print(f"POLICY SCORECARD: {a.label}")
    print("=" * 70)
    print(f"  |I| khai bao        : {len(I)}   {I}")
    if R is not None:
        R = list(dict.fromkeys(R))
        inter = [h for h in R if any(h == d or (d.startswith('*.') and h.endswith(d[1:])) for d in I)]
        cov = len(inter) / len(R) if R else 0
        util = len(inter) / len(I) if I else 0
        unused = [h for h in I if h not in R]
        print(f"  |R| quan sat (S3)   : {len(R)}   {R}")
        print(f"  R ∩ I               : {len(inter)}   {inter}")
        print(f"  --- BUILD SAFETY ---")
        print(f"  Coverage  |R∩I|/|R| : {cov:.2f}   {'DU (build qua)' if cov==1 else 'THIEU -> build hong'}")
        print(f"  --- OVER-PROVISION ---")
        print(f"  Utilization |R∩I|/|I|: {util:.2f}   ({len(inter)}/{len(I)} host thuc su dung)")
        print(f"  Over-declaration    : {1-util:.2f}   ({len(unused)} host thua: {unused})")
    print(f"  --- RESIDUAL REACH ---")
    print(f"  |E| reach           : {len(E)}")
    print(f"  Expansion |E|/|I|   : {len(E)/len(I):.1f}x")
    if R is not None:
        tight = len(R) / len(E) if E else 0
        print(f"  Tightness |R|/|E|   : {tight:.3f}   (1.0 = khong the chat hon)")
    if edetail:
        print(f"  --- shared-IP co-tenancy (nguon expansion) ---")
        for h, co in edetail.items():
            print(f"    {h} chia IP voi {len(co)} domain, vd: {co[:4]}")
    # S2 annotate
    flagged = [(h, s2[h]["flags"]) for h in I if h in s2 and s2[h]["flags"]]
    if flagged:
        print(f"  --- S2 annotate ---")
        for h, fl in flagged:
            print(f"    {h}: {fl}")
    print()


if __name__ == "__main__":
    main()
