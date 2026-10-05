#!/usr/bin/env python3
"""
build_s2_reference.py - Xay S2: BANG THAM CHIEU de danh dau domain nghi ngo.

S2 KHONG phai "corpus consensus" (dong thuan tu chinh corpus) — cach do bi
vong lap logic: corpus do cai nguoi ta CHO PHEP, khong phai cai workload CAN,
va corpus cua ta bi chi phoi boi copy-paste/bot.

S2 o day la BA BANG THAM CHIEU DOC LAP voi corpus:

  1. PSL (public_suffix_list.dat, Mozilla)
     -> domain co phai la mot NAMESPACE DA THUE BAO khong?
        Neu dung: ai cung dang ky duoc subdomain ben duoi -> lop A.

  2. LOTS (Living Off Trusted Sites, lots.json)
     -> domain co nam trong danh sach ha tang hop phap TUNG BI dung de
        exfil/C2 khong?

  3. domain -> IP -> domain (cotenancy/resolved.json + tranco/*.jsonl)
     -> IP cua domain nay con phuc vu bao nhieu domain khac?
        Nhieu = enforcement loc theo IP khong phan biet duoc.

Cong them mot bang nho: resolver DoH da biet.

CHAY
    python measurement/build_s2_reference.py
    python measurement/build_s2_reference.py --domains-from data/policies_ci.jsonl
"""
from teep import paths as _P
import argparse
import collections
import json
import re
from pathlib import Path

OUT = Path(str(_P.data("measurement/s2_reference.json")))

# Resolver DoH/DoT cong khai. Nguon: curl DoH wiki + tai lieu nha cung cap.
# Chi co y nghia khi di kem PORT 443/853 (port 53 la DNS thuong, khong ne duoc).
DOH_RESOLVERS = {
    "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
    "dns10.quad9.net", "doh.opendns.com", "dns.adguard-dns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com", "doh.dns.sb", "dns.alidns.com",
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
}
DOH_PORTS = {"443", "853"}


def load_psl(path=str(_P.config("public_suffix_list.dat"))):
    lines = [l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines()]
    try:
        i = next(k for k, l in enumerate(lines) if "BEGIN PRIVATE" in l)
    except StopIteration:
        i = 0
    icann = {l for l in lines[:i] if l and not l.startswith("//")}
    private = {l for l in lines[i:] if l and not l.startswith("//")}
    return icann, private


def psl_class(host, icann, private):
    """Tra (lop, ly_do, suffix_khop) cho MOT host (wildcard hoac khong).

    A = host (hoac base cua wildcard) CHINH LA public suffix -> namespace da thue bao
    B = nam duoi mot public suffix -> mot to chuc kiem soat
    ? = khong khop suffix nao
    """
    h = host.lower().strip().split(":")[0]
    base = re.sub(r"^[^.]*\*[^.]*\.", "", h.lstrip("*").lstrip("."))
    if base in private:
        return "A", "la public suffix (PSL private) — khong gian da thue bao", base
    if base in icann:
        return "A", "la public suffix (PSL ICANN)", base
    parts = base.split(".")
    for k in range(1, len(parts)):
        cand = ".".join(parts[k:])
        if cand in private or cand in icann:
            depth = k
            return "B", f"nam duoi public suffix '{cand}' ({depth} nhan)", cand
    return "?", "khong khop public suffix nao", None


def load_lots(path=str(_P.config("lots.json"))):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return [s.lower() for s in d["list"]], d.get("version", "?")


def lots_hit(host, lots):
    h = host.lower().split(":")[0].lstrip("*").lstrip(".")
    for suf in lots:
        s = suf.lstrip(".")
        if h == s or h.endswith("." + s):
            return suf
    return None


def build_fanin(tranco_path=str(_P.data("tranco/resolved_top100000.jsonl"))):
    """IP -> so domain (trong top-100k Tranco) cung tro toi IP do."""
    ip2dom = collections.defaultdict(set)
    p = Path(tranco_path)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--psl", default=str(_P.config("public_suffix_list.dat")))
    ap.add_argument("--lots", default=str(_P.config("lots.json")))
    ap.add_argument("--resolved", default=str(_P.data("cotenancy/resolved.json")))
    ap.add_argument("--tranco", default=str(_P.data("tranco/resolved_top100000.jsonl")))
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()

    icann, private = load_psl(a.psl)
    lots, lots_ver = load_lots(a.lots)
    resolved = json.loads(Path(a.resolved).read_text(encoding="utf-8"))
    ip2dom = build_fanin(a.tranco)
    print(f"[*] PSL: {len(icann)} ICANN + {len(private)} private")
    print(f"[*] LOTS: {len(lots)} hau to (version {lots_ver})")
    print(f"[*] resolved: {len(resolved)} domain -> IP")
    print(f"[*] Tranco fan-in: {len(ip2dom):,} IP")

    # Tap host can danh dau = moi host xuat hien trong policy co cuong che
    hosts = set()
    with open(a.policies, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            for h in r.get("hosts") or []:
                hosts.add(h.lower())
    print(f"[*] {len(hosts)} host phan biet can danh dau\n")

    table = {}
    for h in sorted(hosts):
        cls, why, suf = psl_class(h, icann, private)
        lt = lots_hit(h, lots)
        ips = resolved.get(h) or []
        # fan-in: tong so domain khac dung chung bat ky IP nao cua host nay
        cotenants = set()
        for ip in ips:
            cotenants |= (ip2dom.get(ip, set()) - {h})
        flags = []
        if "*" in h:
            flags.append("wildcard")
        if cls == "A":
            flags.append("open_namespace")
        if lt:
            flags.append("lots")
        if h.split(":")[0] in DOH_RESOLVERS:
            flags.append("doh_resolver")
        if len(cotenants) >= 1:
            flags.append("shared_ip")
        table[h] = {
            "psl_class": cls, "psl_reason": why, "psl_suffix": suf,
            "lots_match": lt,
            "n_ips": len(ips), "ips": ips[:8],
            "n_cotenants": len(cotenants),
            "cotenant_sample": sorted(cotenants)[:5],
            "flags": flags,
            "suspicious": bool(flags) and flags != ["wildcard"],
        }

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({
        "meta": {"psl_private": len(private), "lots_version": lots_ver,
                 "n_resolved": len(resolved), "n_tranco_ips": len(ip2dom)},
        "hosts": table,
    }, indent=1, ensure_ascii=False), encoding="utf-8")

    # --- tom tat ---
    c = collections.Counter()
    for v in table.values():
        for fl in v["flags"]:
            c[fl] += 1
        if not v["flags"]:
            c["clean"] += 1
    n = len(table)
    print("=" * 66)
    print("S2 — DANH DAU HOST BANG BA BANG THAM CHIEU")
    print("=" * 66)
    for k, v in c.most_common():
        print(f"  {k:18s} {v:6d}  ({100*v/n:5.1f}%)")
    print(f"  {'TONG':18s} {n:6d}")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
