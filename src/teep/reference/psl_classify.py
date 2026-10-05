#!/usr/bin/env python3
"""
psl_classify.py - Phan loai wildcard theo Public Suffix List, thay cho danh sach tu lam.

VI SAO DUNG PSL
  PSL la danh sach do Mozilla duy tri, liet ke cac hau to ma "cac to chuc doc lap
  kiem soat noi dung ben duoi". Trinh duyet dung no de xac dinh ranh gioi origin/cookie.
  Voi ban, no la mot CHUAN CO SAN thay cho danh sach ban tu go — reviewer khong the
  hoi "sao ban chon nhung ten nay".

QUY TAC PHAN LOAI (chinh xac, khong mo ho)
  Cho wildcard *.X :
    X la public suffix         -> A  wildcard trum CA MOT khong gian da thue bao
                                     vd *.blob.core.windows.net, *.githubusercontent.com
    X la eTLD+1 (dang ky duoc) -> B  wildcard chi trum subdomain cua MOT to chuc
                                     vd *.actions.githubusercontent.com, *.github.com
    X sau hon eTLD+1           -> B  hep hon nua

CAI DAT
    pip install requests

CHAY
    python psl_classify.py                       # tai PSL roi phan loai corpus
    python psl_classify.py --src data/policies_ci.jsonl
"""

from teep import paths as _P
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

PSL_URL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
PSL_FILE = Path(str(_P.config("public_suffix_list.dat")))

# Namespace da thue bao NHUNG chua co trong PSL. Moi dong phai co nguon.
# Day la phan BO SUNG, bao cao rieng voi phan PSL.
SUPPLEMENT = {
    "r2.cloudflarestorage.com": "Cloudflare R2: subdomain la account ID, ai cung tao duoc",
    "storage.googleapis.com":   "GCS: subdomain la ten bucket toan cau duy nhat",
    "amazonaws.com":            "trum len s3.amazonaws.com va cac public suffix con khac",
}

# Namespace ma tenancy nam trong PATH chu khong phai subdomain -> KHONG phai lop A
PATH_TENANCY = {
    "pkg.dev": "Google Artifact Registry: project nam trong path, subdomain la region",
}


def load_psl(force=False):
    if force or not PSL_FILE.exists():
        import requests
        r = requests.get(PSL_URL, timeout=120)
        r.raise_for_status()
        PSL_FILE.write_text(r.text, encoding="utf-8")
    lines = [l.strip() for l in PSL_FILE.read_text(encoding="utf-8").splitlines()]
    try:
        i = next(k for k, l in enumerate(lines) if "BEGIN PRIVATE" in l)
    except StopIteration:
        i = 0
    icann = {l for l in lines[:i] if l and not l.startswith("//")}
    private = {l for l in lines[i:] if l and not l.startswith("//")}
    return icann, private


def longest_suffix(host, suffixes):
    """Tra ve public suffix dai nhat khop host, hoac None."""
    parts = host.split(".")
    for k in range(len(parts)):
        cand = ".".join(parts[k:])
        if cand in suffixes:
            return cand
        if "*." + ".".join(parts[k + 1:]) in suffixes and k > 0:
            return cand
    return None


def classify(pattern, icann, private):
    """Tra (class, reason, matched_suffix)."""
    host = pattern.lower().strip().split(":")[0]
    if "*" not in host:
        return None, "khong phai wildcard", None
    base = re.sub(r"^[^.]*\*[^.]*\.", "", host.lstrip("*").lstrip("."))

    if base in PATH_TENANCY:
        return "B", "tenancy nam trong path: " + PATH_TENANCY[base], None
    if base in SUPPLEMENT:
        return "A", "bo sung ngoai PSL: " + SUPPLEMENT[base], None

    all_suf = icann | private
    if base in private:
        return "A", "base CHINH LA public suffix (PSL private) — trum ca khong gian da thue bao", base
    if base in icann:
        return "A", "base chinh la public suffix (PSL ICANN)", base

    suf = longest_suffix(base, all_suf)
    if suf and suf != base:
        depth = len(base.split(".")) - len(suf.split("."))
        if depth == 1:
            return "B", f"base la eTLD+1 duoi public suffix '{suf}' — mot to chuc kiem soat", suf
        return "B", f"base sau hon eTLD+1 ({depth} nhan duoi '{suf}')", suf
    return "?", "khong khop public suffix nao — kiem tra tay", None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--out", default=str(_P.data("psl_classification.json")))
    a = ap.parse_args()

    icann, private = load_psl(a.refresh)
    print(f"PSL: {len(icann)} ICANN + {len(private)} private suffix\n")

    src = Path(a.src)
    if not src.exists():
        raise SystemExit(f"Khong thay {src}")

    pat_count = Counter()
    pat_repos = defaultdict(set)
    pol_class = defaultdict(set)      # class -> set of policy key
    repo_class = defaultdict(set)
    n_pol, all_repo = 0, set()

    with src.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            eps = r.get("endpoints") or r.get("hosts") or []
            if not eps:
                continue
            n_pol += 1
            all_repo.add(r["repo"])
            key = (r["repo"], r.get("path"), r.get("job"), r.get("step_idx"))
            for e in eps:
                if "*" not in str(e):
                    continue
                p = str(e).split(":")[0].lower()
                pat_count[p] += 1
                pat_repos[p].add(r["repo"])
                cls, _, _ = classify(p, icann, private)
                if cls:
                    pol_class[cls].add(key)
                    repo_class[cls].add(r["repo"])

    print("=" * 78)
    print("PHAN LOAI WILDCARD THEO PUBLIC SUFFIX LIST")
    print("=" * 78)
    print(f"  Policy co cuong che, doc duoc : {n_pol}   |   repo: {len(all_repo)}\n")
    print(f"  {'Lop':4s}{'allowlist':>12s}{'%':>8s}{'repo':>10s}{'%':>8s}")
    for c in ["A", "B", "?"]:
        np_, nr = len(pol_class[c]), len(repo_class[c])
        print(f"  {c:4s}{np_:12d}{100*np_/max(n_pol,1):7.1f}%{nr:10d}{100*nr/max(len(all_repo),1):7.1f}%")

    print(f"\n  Chi tiet tung pattern:")
    print(f"  {'n':>5s}  {'pattern':44s} {'lop':4s} ly do")
    for p, n in pat_count.most_common(40):
        cls, why, suf = classify(p, icann, private)
        print(f"  {n:5d}  {p:44s} {cls or '-':4s} {why}")

    out = {"n_policies": n_pol, "n_repos": len(all_repo),
           "by_class": {c: {"policies": len(pol_class[c]), "repos": len(repo_class[c])}
                        for c in pol_class},
           "patterns": [{"pattern": p, "count": n, "repos": len(pat_repos[p]),
                         "class": classify(p, icann, private)[0],
                         "reason": classify(p, icann, private)[1]}
                        for p, n in pat_count.most_common()]}
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")

    print("\n" + "=" * 78)
    print("CACH BAO CAO")
    print("=" * 78)
    print("  Bao cao HAI con so tach nhau:")
    print("    (1) theo PSL   — chuan do Mozilla duy tri, khong ai cai duoc")
    print("    (2) bo sung    — namespace da thue bao chua co trong PSL, liet ke tung cai")
    print("  Va bao cao ca cac cho PSL KHONG DONG Y voi truc giac ban dau.")
    print("  Do la tinh trung thuc phuong phap, reviewer danh gia cao.")


if __name__ == "__main__":
    main()
