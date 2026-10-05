#!/usr/bin/env python3
"""
doh_count.py - Dem entry cho phep phan giai ten mien ngoai luong DNS bi giam sat.

TAI SAO QUAN TRONG:
Harden-Runner chan egress bang cach chan DNS query cua runner. Neu allowlist
cho phep mot resolver DoH (vi du dns.google), runner phan giai duoc BAT KY ten
nao qua HTTPS toi resolver do — lop chan DNS bi vo hoan toan.

Day chinh la CVE-2026-32947 / GHSA-46g3-37rh-v698, va la co che noi rong thu ba
trong khung do luong. Voi mot policy dinh loi nay, tap dich thuc te la TOAN
INTERNET, khong phai mot con so dem duoc.

CHAY
    python doh_count.py
    python doh_count.py --list          # in ra tung policy dinh loi
    python doh_count.py --csv out.csv   # xuat de doi chieu tay

DAU VAO: data/policies_ci.jsonl (da co san)
"""

from teep import paths as _P
import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# TAP RESOLVER — ten mien
# Nguon: tai lieu cong khai cua tung nha cung cap + danh sach public DoH server.
# Moi muc deu la endpoint DoH/DoT da duoc cong bo, khong phai suy doan.
# ---------------------------------------------------------------------------
DOH_NAMES = {
    # Google
    "dns.google", "dns.google.com",
    # Cloudflare
    "cloudflare-dns.com", "one.one.one.one",
    "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    # Quad9
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.quad9.net",
    # OpenDNS / Cisco
    "doh.opendns.com", "doh.familyshield.opendns.com", "doh.sandbox.opendns.com",
    # NextDNS
    "dns.nextdns.io",
    # AdGuard
    "dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
    "dns.adguard-dns.com",
    # CleanBrowsing
    "doh.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org",
    "security-filter-dns.cleanbrowsing.org",
    # Khac
    "doh.mullvad.net", "dns.controld.com", "doh.dns.sb", "dns.sb",
    "doh.libredns.gr", "dnsforge.de", "odvr.nic.cz",
    "dns.digitale-gesellschaft.ch", "doh-de.blahdns.com", "doh-jp.blahdns.com",
    "resolver.dnscrypt.info", "doh.tiar.app", "jp.tiar.app",
    # Trung Quoc
    "dns.alidns.com", "doh.pub", "dot.pub", "doh.360.cn",
}

# IP tran cua resolver cong cong — mot so policy ghi thang IP
DOH_IPS = {
    "8.8.8.8", "8.8.4.4",                       # Google
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3", # Cloudflare
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "9.9.9.11",  # Quad9
    "208.67.222.222", "208.67.220.220",         # OpenDNS
    "94.140.14.14", "94.140.15.15",             # AdGuard
    "185.228.168.9", "185.228.169.9",           # CleanBrowsing
    "76.76.2.0", "76.76.10.0",                  # ControlD
    "223.5.5.5", "223.6.6.6",                   # AliDNS
    "119.29.29.29",                             # DNSPod
}

# Nhan dien theo mau ten, bat cac resolver khong co trong danh sach cung
DOH_PATTERN = re.compile(
    r"(^|\.)(doh|dns|resolver)[0-9]*(-[a-z]+)?\.|"     # doh.x  dns.x  resolver.x
    r"\bdns-query\b|\bdoh\b",
    re.I,
)

PORT_DOT = "853"     # DNS over TLS
PORT_DNS = "53"      # DNS thuong


def split_hostport(ep):
    ep = str(ep).strip().strip("\"'")
    if ":" in ep:
        h, _, p = ep.rpartition(":")
        if p.isdigit():
            return h.lower(), p
    return ep.lower(), None


def classify(ep):
    """Tra ve (muc_do, ly_do) hoac None neu entry khong lien quan DNS."""
    host, port = split_hostport(ep)

    if host in DOH_NAMES:
        return "CONFIRMED", "resolver DoH cong cong da biet"
    if host in DOH_IPS:
        return "CONFIRMED", "IP resolver cong cong da biet"
    if port == PORT_DOT:
        return "CONFIRMED", f"port {PORT_DOT} — DNS over TLS"
    if port == PORT_DNS:
        return "LIKELY", f"port {PORT_DNS} — DNS thuong, ra ngoai luong giam sat"
    if DOH_PATTERN.search(host):
        return "SUSPECTED", "ten goi y endpoint DNS — phai kiem tra tay"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--all-policies", action="store_true",
                    help="dem tren moi policy enforced (tap tho), khong chi 7,137 cua bai bao")
    ap.add_argument("--out", default=str(_P.data("measurement/doh_count_result.json")),
                    help="ghi so lieu tong hop (tests/golden_numbers.json dung file nay)")
    ap.add_argument("--list", action="store_true", help="in tung policy dinh loi")
    ap.add_argument("--csv", help="xuat file CSV de kiem tra tay")
    a = ap.parse_args()

    src = Path(a.src)
    if not src.exists():
        raise SystemExit(f"Khong thay {src}")

    # Quan the cua bai bao: DUNG 7,137 policy cua load_policies() (enforced, khong
    # template hoa, >=1 host dang ten mien). Khong co --all-policies thi chi dem
    # tren tap nay; con so cu 7,590 la tap tho truoc khi loc.
    from teep.capacity.compute_residual_capacity import load_policies
    paper_keys = None
    if not a.all_policies:
        paper_keys = {(p["repo"], p["path"], p["job"], p["step_idx"])
                      for p in load_policies(str(src))}

    n_dohdot_port = 0
    dohdot_keys = set()
    n_pol = 0
    all_repos = set()
    hit_repos = defaultdict(set)          # muc_do -> {repo}
    hit_pols = defaultdict(int)           # muc_do -> so allowlist
    which = Counter()                     # entry cu the -> so lan
    reasons = defaultdict(Counter)
    rows = []
    seen_pol = set()

    with src.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("enforced"):
                continue
            hosts = r.get("hosts") or []
            eps = r.get("endpoints") or hosts
            if not eps or r.get("uses_templating"):
                continue

            # khoa duy nhat cho mot allowlist (tranh dem trung nhu bug cu)
            key = (r["repo"], r.get("path"), r.get("job"), r.get("step_idx"))
            if key in seen_pol:
                continue
            if paper_keys is not None and key not in paper_keys:
                continue
            seen_pol.add(key)

            n_pol += 1
            all_repos.add(r["repo"])

            found = {}
            for ep in eps:
                c = classify(ep)
                if c:
                    lvl, why = c
                    h_, p_ = split_hostport(ep)
                    if (h_ in DOH_NAMES or h_ in DOH_IPS) and p_ in ("443", PORT_DOT):
                        dohdot_keys.add(key)
                    found.setdefault(lvl, []).append((ep, why))
                    which[ep] += 1
                    reasons[lvl][why] += 1

            for lvl, items in found.items():
                hit_pols[lvl] += 1
                hit_repos[lvl].add(r["repo"])
                if a.csv or a.list:
                    for ep, why in items:
                        rows.append({
                            "level": lvl, "repo": r["repo"], "path": r.get("path"),
                            "job": r.get("job"), "entry": ep, "reason": why,
                            "n_entries": len(eps),
                        })

    nr = len(all_repos)

    out = {
        "n_policy": n_pol, "n_repo": nr,
        "n_resolver_endpoints": len(DOH_NAMES) + len(DOH_IPS),
        "n_confirmed": hit_pols.get("CONFIRMED", 0),
        "n_confirmed_repos": len(hit_repos.get("CONFIRMED", ())),
        "n_port53": hit_pols.get("LIKELY", 0),
        "n_suspected": hit_pols.get("SUSPECTED", 0),
        "n_doh_dot_port_policies": len(dohdot_keys),
        "population": "all enforced" if a.all_policies else "load_policies (paper, n=7137)",
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")

    def pc(x, tot):
        return f"{100*x/tot:.2f}%" if tot else "n/a"

    print("=" * 74)
    print("CO CHE NOI RONG THU BA — PHAN GIAI TEN NGOAI LUONG DNS BI GIAM SAT")
    print("=" * 74)
    print(f"  Allowlist co hieu luc, doc duoc : {n_pol}")
    print(f"  Repo rieng biet                 : {nr}")
    print()
    print(f"  {'Muc do':12s}{'allowlist':>12s}{'':>9s}{'repo':>8s}")
    for lvl in ("CONFIRMED", "LIKELY", "SUSPECTED"):
        p, rr = hit_pols.get(lvl, 0), len(hit_repos.get(lvl, ()))
        print(f"  {lvl:12s}{p:12d} {pc(p, n_pol):>8s}{rr:8d} {pc(rr, nr):>8s}")

    tot_p = len(set().union(*[set() for _ in ()])) if False else None
    any_p = sum(1 for _ in ())  # placeholder khong dung

    print()
    if which:
        print("  Entry cu the tim thay:")
        for ep, c in which.most_common(30):
            lvl, why = classify(ep)
            print(f"    {c:5d}  [{lvl:9s}] {ep:45s} {why}")
    else:
        print("  Khong tim thay entry nao lien quan DNS.")

    print()
    print("=" * 74)
    print("DIEN GIAI")
    print("=" * 74)
    conf = hit_pols.get("CONFIRMED", 0)
    if conf:
        print(f"  {conf} allowlist ({pc(conf, n_pol)}) cho phep phan giai ten qua mot")
        print(f"  kenh nam ngoai lop DNS bi giam sat.")
        print(f"  Voi nhung policy nay, |E| KHONG CHAN TREN — khong phai vi co-tenancy,")
        print(f"  ma vi bat ky ten nao cung phan giai duoc.")
        print(f"  -> Xep vao LOP A (unbounded), cung nhom voi wildcard namespace mo.")
    else:
        print("  Khong allowlist nao dinh loi nay.")
        print()
        print("  DAY VAN LA KET QUA CO GIA TRI, va nen bao cao:")
        print("  Co che bypass da co CVE (CVE-2026-32947) va PoC cong khai, nhung")
        print("  KHONG xuat hien trong policy thuc te. Nghia la rui ro nay mang tinh")
        print("  ly thuyet trong corpus nay, khac han voi wildcard namespace mo —")
        print("  von xuat hien that va do chinh tai lieu nha cung cap yeu cau.")
        print()
        print("  Cau phat bieu: 'The DoH bypass is documented and has an assigned CVE,")
        print("  but appears in zero policies in our corpus. The wildcard exposure,")
        print("  by contrast, appears in N policies and is mandated by vendor")
        print("  documentation. Not all published bypasses are equally present in")
        print("  practice, and measuring which ones are is part of the contribution.'")

    lik = hit_pols.get("LIKELY", 0)
    if lik:
        print()
        print(f"  {lik} allowlist co entry port 53. Can kiem tra tay: neu tro toi")
        print(f"  resolver ben ngoai thi tuong duong DoH; neu tro toi resolver noi bo")
        print(f"  cua runner thi vo hai.")

    sus = hit_pols.get("SUSPECTED", 0)
    if sus:
        print()
        print(f"  {sus} allowlist co entry ten goi y DNS. PHAI kiem tra tay truoc khi")
        print(f"  dua vao bat ky con so nao.")

    if a.list and rows:
        print()
        print("=" * 74)
        print("CHI TIET")
        print("=" * 74)
        for r in rows[:80]:
            print(f"  [{r['level']:9s}] {r['repo']:40s} {r['entry']}")
        if len(rows) > 80:
            print(f"  ... con {len(rows)-80} dong nua, dung --csv de xem het")

    if a.csv and rows:
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\n>>> {a.csv} ({len(rows)} dong)")


if __name__ == "__main__":
    main()
