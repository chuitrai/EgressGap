#!/usr/bin/env python3
"""
dns_cotenancy.py - Do IP co-tenancy cua cac domain hay xuat hien trong egress allowlist.

Cau hoi tra loi: mot domain duoc allow phan giai ve khong gian IP RIENG cua no,
hay ve khong gian IP DUNG CHUNG ma bat ky ai cung host len duoc?

CAI DAT (Git Bash tren Windows)
    pip install dnspython requests

CHAY
    python dns_cotenancy.py fetch-ranges        # tai dai IP cong bo, luu ra dia
    python dns_cotenancy.py resolve             # resolve domain, lap nhieu lan
    python dns_cotenancy.py report              # in bang ket qua

    # dung domain rieng (vi du lay tu hr_crawl.py stats)
    python dns_cotenancy.py resolve --domains-file my_hosts.txt --rounds 5
"""
from teep import paths as _P
import argparse
import ipaddress
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    sys.exit("Thieu requests. Chay: pip install requests dnspython")

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

OUT = _P.data("cotenancy")

# Domain hay gap nhat trong allowlist CI/CD thuc te
DEFAULT_DOMAINS = [
    "github.com", "api.github.com", "codeload.github.com",
    "objects.githubusercontent.com", "raw.githubusercontent.com",
    "pkg-containers.githubusercontent.com", "ghcr.io",
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "proxy.golang.org", "sum.golang.org", "crates.io", "static.crates.io",
    "registry.yarnpkg.com", "repo.maven.apache.org", "rubygems.org",
    "index.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
    "storage.googleapis.com", "s3.amazonaws.com",
    "dns.google", "cloudflare-dns.com",          # resolver DoH - co che (iii)
]

# Nguon dai IP cong bo. Moi nguon: (ten, url, ham trich CIDR)
RANGE_SOURCES = {
    "github":     "https://api.github.com/meta",
    "aws":        "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "cloudflare": "https://www.cloudflare.com/ips-v4",
    "fastly":     "https://api.fastly.com/public-ip-list",
    "google":     "https://www.gstatic.com/ipranges/goog.json",
}

# Microsoft/Azure phai xu ly rieng: KHONG co URL JSON co dinh.
# Trang Download Center sinh ra file ten ServiceTags_Public_YYYYMMDD.json va
# URL doi theo tung ban phat hanh (cap nhat hang tuan). Ta do link tu trang
# tai ve; neu do that bai thi nguoi dung tai tay roi truyen --azure-file.
AZURE_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
AZURE_URL_RE = r"https://download\.microsoft\.com/download/[^\"'\s]*?ServiceTags_Public_\d{8}\.json"


def extract_cidrs(name, payload):
    """Moi nha cung cap tra ve mot dinh dang khac nhau."""
    out = []
    if name == "github":
        d = json.loads(payload)
        for k, v in d.items():
            if isinstance(v, list):
                out += [c for c in v if isinstance(c, str) and "/" in c]
    elif name == "aws":
        d = json.loads(payload)
        out += [p["ip_prefix"] for p in d.get("prefixes", [])]
    elif name == "cloudflare":
        out += [l.strip() for l in payload.splitlines() if l.strip()]
    elif name == "fastly":
        d = json.loads(payload)
        out += d.get("addresses", [])
    elif name == "google":
        d = json.loads(payload)
        out += [p["ipv4Prefix"] for p in d.get("prefixes", []) if "ipv4Prefix" in p]
    return out


def _azure_payload(args):
    """Tra ve (json_text, nguon_mo_ta) hoac (None, ly_do_that_bai)."""
    if args.azure_file:
        p = Path(args.azure_file)
        if not p.exists():
            return None, f"khong thay file {p}"
        return p.read_text(encoding="utf-8"), f"file cuc bo {p.name}"

    # Tu do link JSON moi nhat tu trang Download Center
    try:
        import re
        r = requests.get(AZURE_PAGE, timeout=30,
                         headers={"User-Agent": "Mozilla/5.0 egress-research/0.1"})
        m = re.search(AZURE_URL_RE, r.text)
        if not m:
            return None, ("khong do duoc link JSON tu trang Download Center "
                          "(Microsoft doi bo cuc trang). Tai tay roi dung --azure-file")
        url = m.group(0)
        rj = requests.get(url, timeout=120,
                          headers={"User-Agent": "egress-research/0.1"})
        if rj.status_code != 200:
            return None, f"HTTP {rj.status_code} khi tai {url}"
        return rj.text, url.rsplit("/", 1)[-1]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def extract_azure(payload):
    """Tra ve (cidrs, meta) — meta: cidr -> danh sach (service_tag, region).

    KHONG gop tat ca thanh mot nhan 'azure': giu lai service tag va region
    de phan tich sau nay phan biet duoc Storage / FrontDoor / AzureCloud...
    Mot CIDR co the thuoc NHIEU tag (vd vua AzureCloud vua Storage.WestEurope).
    """
    d = json.loads(payload)
    cidrs, meta = [], defaultdict(list)
    for item in d.get("values", []):
        props = item.get("properties") or {}
        tag = item.get("name", "")
        region = props.get("region", "") or ""
        svc = props.get("systemService", "") or ""
        for pfx in props.get("addressPrefixes", []) or []:
            if ":" in pfx:          # bo IPv6, phan con lai cua pipeline la IPv4
                continue
            try:
                n = str(ipaddress.ip_network(pfx, strict=False))
            except ValueError:
                continue
            cidrs.append(n)
            meta[n].append({"tag": tag, "region": region, "service": svc})
    return sorted(set(cidrs)), meta


def cmd_fetch_ranges(args):
    OUT.mkdir(exist_ok=True)
    store = {}
    for name, url in RANGE_SOURCES.items():
        try:
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": "egress-research/0.1"})
            if r.status_code != 200:
                print(f"  ! {name}: HTTP {r.status_code}, bo qua")
                continue
            cidrs = extract_cidrs(name, r.text)
            nets = []
            for c in cidrs:
                try:
                    nets.append(str(ipaddress.ip_network(c, strict=False)))
                except ValueError:
                    continue
            store[name] = nets
            print(f"  + {name}: {len(nets)} prefix")
        except Exception as e:
            print(f"  ! {name}: {type(e).__name__} {e}")

    # --- Microsoft / Azure ------------------------------------------------
    azure_src = None
    if not args.no_azure:
        payload, info = _azure_payload(args)
        if payload is None:
            print(f"  ! azure: {info}")
            print("    -> Tai tay tai https://www.microsoft.com/en-us/download/details.aspx?id=56519")
            print("       roi chay lai voi: --azure-file ServiceTags_Public_YYYYMMDD.json")
        else:
            try:
                cidrs, meta = extract_azure(payload)
                store["azure"] = cidrs
                azure_src = info
                (OUT / "ranges_azure_meta.json").write_text(
                    json.dumps({k: v for k, v in meta.items()}, indent=1),
                    encoding="utf-8")
                n_tags = len({t["tag"] for v in meta.values() for t in v})
                print(f"  + azure: {len(cidrs)} prefix, {n_tags} service tag  [{info}]")
                print(f"    (metadata tag/region -> {OUT/'ranges_azure_meta.json'})")
            except Exception as e:
                print(f"  ! azure: loi doc JSON: {type(e).__name__}: {e}")

    (OUT / "ranges.json").write_text(json.dumps(store), encoding="utf-8")

    # Ghi lai NGUON va NGAY chup — bat buoc de ket qua reproducible,
    # vi cac nha cung cap doi dai IP thuong xuyen (Azure cap nhat hang tuan).
    (OUT / "ranges_provenance.json").write_text(json.dumps({
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": {**RANGE_SOURCES, **({"azure": azure_src} if azure_src else {})},
        "prefix_counts": {k: len(v) for k, v in store.items()},
    }, indent=1), encoding="utf-8")

    total = sum(len(v) for v in store.values())
    print(f"\n>>> {total} prefix tu {len(store)} nha cung cap -> {OUT/'ranges.json'}")
    print(f">>> nguon + ngay chup -> {OUT/'ranges_provenance.json'}")


def resolve_once(domain):
    """Tra ve tap IPv4. Uu tien dnspython, fallback socket."""
    ips = set()
    if HAVE_DNS:
        try:
            res = dns.resolver.Resolver()
            res.lifetime = 5
            for rd in res.resolve(domain, "A"):
                ips.add(rd.address)
            return ips, None
        except Exception as e:
            return ips, f"{type(e).__name__}"
    import socket
    try:
        for info in socket.getaddrinfo(domain, 443, socket.AF_INET):
            ips.add(info[4][0])
    except Exception as e:
        return ips, f"{type(e).__name__}"
    return ips, None


def cmd_resolve(args):
    OUT.mkdir(exist_ok=True)
    if args.domains_file:
        domains = [l.strip() for l in Path(args.domains_file).read_text(encoding="utf-8").splitlines()
                   if l.strip() and not l.startswith("#")]
        domains = [d.split(":")[0] for d in domains]
        domains = [d for d in domains if "*" not in d]
    else:
        domains = DEFAULT_DOMAINS
    seen = defaultdict(set)
    print(f"[*] Bat dau resolve {len(domains):,} domain x {args.rounds} vong (Da luong 50 workers)...\n")
    
    for rnd in range(1, args.rounds + 1):
        print(f"--- Vong {rnd}/{args.rounds}")
        t0 = time.time()
        
        # Chay song song 50 threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_results = list(executor.map(lambda d: (d, resolve_once(d)), domains))
        success_count = 0
        for d, (ips, err) in future_results:
            if ips:
                success_count += 1
                seen[d] |= ips
        print(f"    -> Vong {rnd} hoan tat: {success_count:,}/{len(domains):,} domain resolve thanh cong ({round(time.time()-t0, 1)}s)")
        
        if rnd < args.rounds:
            time.sleep(args.interval)
    data = {d: sorted(v) for d, v in seen.items() if v}
    (OUT / "resolved.json").write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> Da ghi {len(data):,} domain resolve duoc vao {OUT/'resolved.json'}")

def classify(ip, ranges):
    hits = []
    addr = ipaddress.ip_address(ip)
    for provider, nets in ranges.items():
        for n in nets:
            try:
                if addr in ipaddress.ip_network(n):
                    hits.append(provider)
                    break
            except ValueError:
                continue
    return hits


def cmd_report(args):
    rp, dp = OUT / "ranges.json", OUT / "resolved.json"
    if not rp.exists() or not dp.exists():
        sys.exit("Chay 'fetch-ranges' va 'resolve' truoc.")

    ranges = json.loads(rp.read_text())
    resolved = json.loads(dp.read_text())

    # Tien xu ly: danh chi muc theo octet dau. Them Azure la them ~60k prefix;
    # quet tuyen tinh toan bo cho MOI ip se cham hang phut. Chi muc nay cat
    # phan lon phep so sanh vi mot /8 chi chua cac dai bat dau bang octet do.
    idx = defaultdict(list)          # octet dau -> [(network, provider)]
    n_prefix = 0
    for p, v in ranges.items():
        for n in v:
            try:
                net = ipaddress.ip_network(n)
            except ValueError:
                continue
            n_prefix += 1
            if net.prefixlen >= 8:
                idx[int(net.network_address) >> 24].append((net, p))
            else:                    # dai rong hon /8: nam o nhieu octet dau
                lo = int(net.network_address) >> 24
                hi = int(net.broadcast_address) >> 24
                for o in range(lo, hi + 1):
                    idx[o].append((net, p))

    def classify_fast(ip):
        a = ipaddress.ip_address(ip)
        return sorted({p for net, p in idx.get(int(a) >> 24, ()) if a in net})

    ip_to_domains = defaultdict(set)
    rows = []
    for d, ips in sorted(resolved.items()):
        provs = Counter()
        for ip in ips:
            for p in classify_fast(ip):
                provs[p] += 1
            ip_to_domains[ip].add(d)
        rows.append((d, len(ips), dict(provs)))

    print("=" * 78)
    print("BANG 1 - Do on dinh cua tap IP va nha cung cap")
    print("=" * 78)
    print(f"{'domain':42s} {'#IP':>4s}  nha cung cap")
    for d, n, provs in rows:
        p = ", ".join(f"{k}:{v}" for k, v in provs.items()) or "(khong khop dai nao)"
        print(f"{d:42s} {n:4d}  {p}")

    print("\n" + "=" * 78)
    print("BANG 2 - IP dung chung giua nhieu domain (bang chung co-tenancy)")
    print("=" * 78)
    shared = {ip: ds for ip, ds in ip_to_domains.items() if len(ds) > 1}
    if shared:
        for ip, ds in sorted(shared.items(), key=lambda x: -len(x[1]))[:20]:
            print(f"  {ip:16s} <- {len(ds)} domain: {', '.join(sorted(ds))}")
    else:
        print("  (khong thay IP dung chung trong mau nay)")

    all_ips = {ip for ips in resolved.values() for ip in ips}
    matched = {ip for ip in all_ips if classify_fast(ip)}

    print("\n" + "=" * 78)
    print("CON SO CHINH")
    print("=" * 78)
    print(f"  Domain resolve duoc          : {len(resolved)}")
    print(f"  IP unique                    : {len(all_ips)}")
    print(f"  IP nam trong dai CDN/cloud   : {len(matched)} "
          f"({100*len(matched)/len(all_ips):.1f}%)")
    print(f"  IP phuc vu >1 domain         : {len(shared)} "
          f"({100*len(shared)/len(all_ips):.1f}%)")
    multi = [d for d, n, _ in rows if n > 4]
    print(f"  Domain co >4 IP (IP khong on dinh): {len(multi)}/{len(rows)}")
    print("\n  -> Ty le thu 3 la bang chung truc tiep cho co che (i) shared-IP:")
    print("     mot IP phuc vu nhieu domain thi enforcement L3/L4 khong phan biet duoc.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    fr = sub.add_parser("fetch-ranges")
    fr.add_argument("--azure-file",
                    help="duong dan ServiceTags_Public_YYYYMMDD.json tai tay "
                         "(dung khi khong tu do duoc link tu Download Center)")
    fr.add_argument("--no-azure", action="store_true",
                    help="bo qua Microsoft/Azure")
    fr.set_defaults(fn=cmd_fetch_ranges)

    r = sub.add_parser("resolve")
    r.add_argument("--domains-file")
    r.add_argument("--rounds", type=int, default=3)
    r.add_argument("--interval", type=int, default=20)
    r.set_defaults(fn=cmd_resolve)

    sub.add_parser("report").set_defaults(fn=cmd_report)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
