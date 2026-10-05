#!/usr/bin/env python3
"""
sample20.py - Chon 20 policy DA DANG (khong phai 20 policy pho bien nhat).

VI SAO KHONG LAY TOP-20 PHO BIEN: 20 tap host lap lai nhieu nhat trong corpus
gan nhu deu la job quet tu dong (dependency-review, codeql, scorecard) do bot
chen hang loat. Lay chung se do lai mot thu duy nhat 20 lan.

CACH CHON: phan tang (stratified) tren 3 chieu
    - co wildcard hay khong        (2 muc)
    - kich thuoc allowlist          (nho <=4 / vua 5-10 / lon >10)
    - so sao repo                   (0-1 / 2-100 / >100)
=> 18 o. Moi o lay 1 mau, uu tien o co he sinh thai chua xuat hien.

LOAI TRU
    - policy khong doc duoc file workflow (C3 se hong)
    - repo *arm-int-tests cua StepSecurity: repo test noi bo, allowlist chua
      adobe.com/alibaba.com/amazon.com... khong phai workload that
    - tap host TRUNG NHAU: moi tap host chi lay 1 dai dien

CHAY
    python measurement/sample20.py
    python measurement/sample20.py --n 20 --seed 42
"""
from teep import paths as _P
import argparse
import json
import random
import re
from collections import defaultdict
from pathlib import Path

DATA = _P.data("data")
EXCLUDE_REPO = re.compile(r"arm-int-tests|integration-tests?$", re.I)


def size_bucket(n):
    return "nho(<=4)" if n <= 4 else ("vua(5-10)" if n <= 10 else "lon(>10)")


def star_bucket(s):
    return "0-1" if s <= 1 else ("2-100" if s <= 100 else ">100")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/sample20.json")))
    a = ap.parse_args()
    random.seed(a.seed)

    rules = json.loads(Path(a.rules).read_text(encoding="utf-8"))["rules"]
    for r in rules:
        r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]

    blob_of, stars = {}, {}
    with open(DATA / "files_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            blob_of[(d["repo"], d["path"])] = d["blob"]
    with open(DATA / "repos_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            stars[d["repo"]] = d.get("stars", 0) or 0

    seen_hostset = set()
    cands = []
    with open(DATA / "policies_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            hosts = [h.lower() for h in (r.get("hosts") or [])]
            if not hosts:
                continue
            if EXCLUDE_REPO.search(r["repo"]):
                continue
            key = frozenset(hosts)
            if key in seen_hostset:          # moi tap host chi 1 dai dien
                continue
            blob = blob_of.get((r["repo"], r["path"]))
            if not blob:
                continue
            fp = DATA / "files" / blob
            try:
                txt = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            seen_hostset.add(key)
            eco = sorted({rr["ecosystem"] for rr in rules
                          if rr["id"] != "any_action"
                          and any(rx.search(txt) for rx in rr["_re"])})
            cands.append({
                "repo": r["repo"], "path": r["path"], "job": r.get("job"),
                "step_idx": r.get("step_idx"), "blob": blob,
                "hosts": sorted(hosts), "n_hosts": len(hosts),
                "has_wildcard": any("*" in h for h in hosts),
                "stars": stars.get(r["repo"], 0),
                "ecosystems": eco,
                "size_bucket": size_bucket(len(hosts)),
                "star_bucket": star_bucket(stars.get(r["repo"], 0)),
            })

    print(f"[*] {len(cands)} ung vien (tap host phan biet, doc duoc file, da loai repo test)")

    cells = defaultdict(list)
    for c in cands:
        cells[(c["has_wildcard"], c["size_bucket"], c["star_bucket"])].append(c)
    print(f"[*] {len(cells)} o phan tang co du lieu\n")

    picked, used_eco = [], set()
    for key in sorted(cells, key=lambda k: (str(k[0]), k[1], k[2])):
        pool = cells[key]
        # uu tien mau mang he sinh thai CHUA xuat hien
        fresh = [c for c in pool if set(c["ecosystems"]) - used_eco]
        pick = random.choice(fresh or pool)
        picked.append(pick)
        used_eco |= set(pick["ecosystems"])

    # bo sung cho du n, uu tien he sinh thai moi
    rest = [c for c in cands if c not in picked]
    random.shuffle(rest)
    rest.sort(key=lambda c: -len(set(c["ecosystems"]) - used_eco))
    while len(picked) < a.n and rest:
        p = rest.pop(0)
        picked.append(p)
        used_eco |= set(p["ecosystems"])
    picked = picked[:a.n]

    for i, p in enumerate(picked, 1):
        p["sample_id"] = f"P{i:02d}"

    Path(a.out).write_text(json.dumps(
        {"seed": a.seed, "n": len(picked), "policies": picked},
        indent=1, ensure_ascii=False), encoding="utf-8")

    print("=" * 96)
    print(f"{'id':4s} {'repo':38s} {'#h':>3s} {'wc':>3s} {'sao':>6s}  he sinh thai")
    print("-" * 96)
    for p in picked:
        print(f"{p['sample_id']:4s} {p['repo'][:38]:38s} {p['n_hosts']:3d} "
              f"{'Y' if p['has_wildcard'] else '-':>3s} {p['stars']:6d}  "
              f"{','.join(p['ecosystems'])[:32]}")
    print("\nPhu he sinh thai:", ", ".join(sorted(used_eco)) or "(khong)")
    print(f">>> {a.out}")


if __name__ == "__main__":
    main()
