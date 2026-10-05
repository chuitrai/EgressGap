#!/usr/bin/env python3
"""
tranco_cotenancy.py - Do HE SO NOI RONG cua co che enforcement L3/L4.

CAU HOI: mot allowlist ghi N domain. Neu firewall loc theo IP, tap dich THUC TE
la bao nhieu domain? Moi domain khac phan giai ve cung IP deu di qua duoc.

CACH LAM:
  1. Tai Tranco top-1M (bang xep hang domain chuan trong nghien cuu, peer-reviewed)
  2. Resolve top-N domain -> xay index IP -> {domain}
  3. Voi moi host trong allowlist, tra IP cua no -> dem co bao nhieu domain LA
     cung dung IP do

KET QUA: "allow 1 domain qua firewall IP thi thuc te mo duong toi K domain."
Do la mot con so, khong phai mot y kien.

CAI DAT
    pip install dnspython requests

CHAY (buoc 2 chay hang gio - bat roi di doc paper)
    python tranco_cotenancy.py download
    python tranco_cotenancy.py resolve --top 100000 --workers 40
    python tranco_cotenancy.py report

RESUMABLE: Ctrl+C bat cu luc nao, chay lai cung lenh se tiep tuc tu checkpoint.

LUU Y DAO DUC: chi gui truy van DNS, khong ket noi toi bat ky host nao.
Day la thu thap du lieu thu dong, khong tac dong len ha tang ben thu ba.
"""

from teep import paths as _P
import argparse
import csv
import io
import json
import os
import sys
import threading
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import requests
    import dns.resolver
except ImportError:
    sys.exit("Thieu thu vien. Chay: pip install dnspython requests")

OUT = _P.data("tranco")
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def log(m):
    print(m, flush=True)


# ------------------------------------------------------------------ download
def cmd_download(args):
    OUT.mkdir(exist_ok=True)
    dst = OUT / "top-1m.csv"
    if dst.exists() and not args.force:
        n = sum(1 for _ in dst.open(encoding="utf-8"))
        log(f"Da co {dst} ({n} dong). Dung --force de tai lai.")
        return
    log(f"Tai {TRANCO_URL} ...")
    r = requests.get(TRANCO_URL, timeout=180,
                     headers={"User-Agent": "egress-research/0.1 (academic)"})
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = z.namelist()[0]
        dst.write_bytes(z.read(name))
    n = sum(1 for _ in dst.open(encoding="utf-8"))
    log(f">>> {dst} ({n} dong)")
    log("    Nho ghi lai NGAY TAI va PHIEN BAN danh sach vao paper —")
    log("    Tranco doi hang ngay, ket qua khong tai lap duoc neu thieu.")


# ------------------------------------------------------------------ resolve
_lock = threading.Lock()


def make_resolver(nameservers=None, timeout=3.0):
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    if nameservers:
        r.nameservers = nameservers
    return r


def resolve_one(res, domain):
    try:
        ans = res.resolve(domain, "A")
        return domain, sorted({rd.address for rd in ans}), None
    except dns.resolver.NXDOMAIN:
        return domain, [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return domain, [], "NoAnswer"
    except dns.resolver.NoNameservers:
        return domain, [], "NoNameservers"
    except Exception as e:
        return domain, [], type(e).__name__


def cmd_resolve(args):
    OUT.mkdir(exist_ok=True)
    src = OUT / "top-1m.csv"
    if not src.exists():
        sys.exit("Chua co top-1m.csv. Chay 'download' truoc.")

    ckpt = OUT / f"resolved_top{args.top}.jsonl"
    done = set()
    if ckpt.exists():
        with ckpt.open(encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["d"])
                except Exception:
                    pass
        log(f"Checkpoint: da resolve {len(done)} domain, bo qua.")

    todo = []
    with src.open(encoding="utf-8") as f:
        for i, row in enumerate(csv.reader(f)):
            if i >= args.top:
                break
            if len(row) >= 2 and row[1] not in done:
                todo.append(row[1])
    log(f"Can resolve {len(todo)} domain voi {args.workers} luong.")
    if not todo:
        log("Khong con gi de lam.")
        return

    ns = args.nameservers.split(",") if args.nameservers else None
    local = threading.local()

    def work(d):
        if not hasattr(local, "res"):
            local.res = make_resolver(ns, args.timeout)
        return resolve_one(local.res, d)

    t0 = time.time()
    n_ok = n_err = 0
    buf = []
    fh = ckpt.open("a", encoding="utf-8")
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(work, d): d for d in todo}
            for i, fut in enumerate(as_completed(futs), 1):
                d, ips, err = fut.result()
                buf.append(json.dumps({"d": d, "ips": ips,
                                       **({"e": err} if err else {})}))
                if err:
                    n_err += 1
                else:
                    n_ok += 1
                if len(buf) >= 500:
                    fh.write("\n".join(buf) + "\n")
                    fh.flush()
                    buf.clear()
                if i % 2000 == 0:
                    el = time.time() - t0
                    rate = i / el
                    log(f"  {i}/{len(todo)} | ok={n_ok} err={n_err} | "
                        f"{rate:.0f}/s | con ~{(len(todo)-i)/rate/60:.0f} phut")
    except KeyboardInterrupt:
        log("\n[!] Dung. Checkpoint da luu, chay lai lenh cu de tiep tuc.")
    finally:
        if buf:
            fh.write("\n".join(buf) + "\n")
        fh.close()
    log(f">>> {ckpt} | ok={n_ok} err={n_err} | {time.time()-t0:.0f}s")


# ------------------------------------------------------------------ report
def load_allowlist_ips():
    """Lay IP cua cac host trong allowlist tu cotenancy/resolved.json."""
    p = Path(str(_P.data("cotenancy/resolved.json")))
    if not p.exists():
        sys.exit("Chua co cotenancy/resolved.json. "
                 "Chay dns_cotenancy.py resolve truoc.")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_report(args):
    ckpt = OUT / f"resolved_top{args.top}.jsonl"
    if not ckpt.exists():
        sys.exit(f"Chua co {ckpt}. Chay 'resolve' truoc.")

    log("Xay index IP -> domain tu Tranco ...")
    ip2dom = defaultdict(set)
    n = 0
    with ckpt.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            n += 1
            for ip in r.get("ips", []):
                ip2dom[ip].add(r["d"])
    log(f"  {n} domain Tranco -> {len(ip2dom)} IP unique")

    allow = load_allowlist_ips()
    rows = []
    for host, ips in sorted(allow.items()):
        if not ips:
            continue
        co = set()
        for ip in ips:
            co |= ip2dom.get(ip, set())
        co.discard(host)
        rows.append({
            "host": host, "n_ip": len(ips), "n_cotenant": len(co),
            "sample": sorted(co)[:5],
        })

    rows.sort(key=lambda r: -r["n_cotenant"])
    tot = len(rows)
    if not tot:
        sys.exit("Khong co host nao resolve duoc.")

    have = [r for r in rows if r["n_cotenant"] > 0]
    counts = sorted(r["n_cotenant"] for r in rows)
    med = counts[len(counts) // 2]

    log("\n" + "=" * 74)
    log("HE SO NOI RONG CUA CO CHE L3/L4")
    log("=" * 74)
    log(f"  Host trong allowlist resolve duoc : {tot}")
    log(f"  Co >=1 co-tenant trong Tranco top-{args.top} : "
        f"{len(have)} ({100*len(have)/tot:.1f}%)")
    log(f"  So co-tenant: median={med}  "
        f"p90={counts[int(.9*len(counts))]}  max={counts[-1]}")
    log(f"\n  20 host co nhieu co-tenant nhat:")
    log(f"  {'host':44s}{'#IP':>5s}{'#co-tenant':>12s}")
    for r in rows[:20]:
        log(f"  {r['host']:44s}{r['n_ip']:5d}{r['n_cotenant']:12d}")

    log(f"\n  Vi du cu the (de ke trong paper):")
    for r in rows[:3]:
        log(f"    allow '{r['host']}' -> cung mo duong toi {r['n_cotenant']} "
            f"domain khac, vi du: {', '.join(r['sample'][:4])}")

    out = OUT / "cotenancy_report.json"
    out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    log(f"\n>>> {out}")

    log(f"\n  CACH PHAT BIEU:")
    log(f"    \"Voi enforcement dua tren IP, mot entry allowlist trung vi mo")
    log(f"     duong toi {med} domain khac trong Tranco top-{args.top}.\"")
    log(f"    Day la CHAN DUOI: chi dem domain trong Tranco, khong dem domain")
    log(f"    ngoai bang xep hang. Con so that con lon hon.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("download")
    d.add_argument("--force", action="store_true")
    d.set_defaults(fn=cmd_download)
    r = sub.add_parser("resolve")
    r.add_argument("--top", type=int, default=100000)
    r.add_argument("--workers", type=int, default=40)
    r.add_argument("--timeout", type=float, default=3.0)
    r.add_argument("--nameservers", help="vd 1.1.1.1,8.8.8.8 (mac dinh: he thong)")
    r.set_defaults(fn=cmd_resolve)
    p = sub.add_parser("report")
    p.add_argument("--top", type=int, default=100000)
    p.set_defaults(fn=cmd_report)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
