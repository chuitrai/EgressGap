#!/usr/bin/env python3
"""
validate_static_rules.py - Kiem chung bang luat S1 bang chinh corpus.

CAU HOI: voi moi luat "pattern P trong workflow => can domain D",
trong so cac policy CO pattern P, bao nhieu % that su cho phep D?

  - Ty le cao  -> luat khop voi thuc te, dung duoc lam S1
  - Ty le thap -> hoac luat sai, HOAC nguoi viet policy quen khai D
                  (ca hai deu la phat hien, phai doc tay moi ket luan duoc)

LUU Y DIEN GIAI (quan trong, dung bo qua):
  Con so nay KHONG phai precision that. No do su DONG THUAN giua luat va
  allowlist do nguoi viet. Allowlist co the sai (thua hoac thieu). Muon
  precision that phai co S3 (quan sat traffic that) lam trong tai.

CHAY
    python measurement/validate_static_rules.py
    python measurement/validate_static_rules.py --rules measurement/static_rules.json
"""
from teep import paths as _P
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

DATA = _P.data("data")


def host_matches(pred, hosts):
    """pred co the la wildcard '*.x.com'. hosts la tap host trong allowlist."""
    pred = pred.lower()
    if pred.startswith("*."):
        suf = pred[1:]                      # '.x.com'
        return any(h == pred or h.endswith(suf) for h in hosts)
    return pred in hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--files", default=str(_P.data("data/files_ci.jsonl")))
    ap.add_argument("--out", default=str(_P.data("measurement/static_rules_validation.json")))
    a = ap.parse_args()

    rules = json.loads(Path(a.rules).read_text(encoding="utf-8"))["rules"]
    for r in rules:
        r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]

    # (repo, path) -> blob
    blob_of = {}
    with open(a.files, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            blob_of[(d["repo"], d["path"])] = d["blob"]

    # doc policy co cuong che, doc duoc
    pols = []
    with open(a.policies, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            hosts = r.get("hosts") or []
            if not hosts:
                continue
            pols.append(r)
    print(f"[*] {len(pols)} policy co cuong che + allowlist doc duoc")

    # cache noi dung workflow (nhieu policy cung mot file)
    text_cache = {}

    def workflow_text(repo, path):
        key = (repo, path)
        if key in text_cache:
            return text_cache[key]
        blob = blob_of.get(key)
        t = ""
        if blob:
            fp = DATA / "files" / blob
            try:
                t = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                t = ""
        text_cache[key] = t
        return t

    stats = {r["id"]: {"matched": 0, "hit_any": 0, "per_domain": defaultdict(int),
                       "examples_miss": []} for r in rules}
    n_no_text = 0

    for p in pols:
        txt = workflow_text(p["repo"], p["path"])
        if not txt:
            n_no_text += 1
            continue
        hosts = {h.lower() for h in p["hosts"]}
        for r in rules:
            if not any(rx.search(txt) for rx in r["_re"]):
                continue
            s = stats[r["id"]]
            s["matched"] += 1
            hit = False
            for d in r["domains"]:
                if host_matches(d, hosts):
                    s["per_domain"][d] += 1
                    hit = True
            if hit:
                s["hit_any"] += 1
            elif len(s["examples_miss"]) < 3:
                s["examples_miss"].append(
                    {"repo": p["repo"], "path": p["path"],
                     "hosts": sorted(hosts)[:8]})

    if n_no_text:
        print(f"[!] {n_no_text} policy khong doc duoc file workflow, da bo qua")

    print()
    print("=" * 86)
    print("KIEM CHUNG BANG LUAT S1 TREN CORPUS")
    print("=" * 86)
    print(f"{'luat':22s} {'conf':7s} {'#khop':>7s} {'>=1 domain':>11s} {'ty le':>8s}")
    print("-" * 86)
    rows = []
    for r in rules:
        s = stats[r["id"]]
        m, h = s["matched"], s["hit_any"]
        pct = 100 * h / m if m else 0.0
        rows.append((r, s, m, h, pct))
    for r, s, m, h, pct in sorted(rows, key=lambda x: -x[4]):
        flag = "  <-- THAP, xem lai" if (m >= 20 and pct < 50) else ""
        print(f"{r['id']:22s} {r.get('confidence','?'):7s} {m:7d} {h:11d} {pct:7.1f}%{flag}")

    print()
    print("=" * 86)
    print("CHI TIET TUNG DOMAIN (trong so policy khop pattern, bao nhieu % cho phep domain do)")
    print("=" * 86)
    for r, s, m, h, pct in sorted(rows, key=lambda x: -x[4]):
        if not m:
            print(f"\n{r['id']}: khong policy nao khop pattern")
            continue
        print(f"\n{r['id']}  (khop {m} policy)")
        for d in r["domains"]:
            c = s["per_domain"].get(d, 0)
            print(f"    {d:52s} {c:6d}  {100*c/m:5.1f}%")

    out = {
        "n_policies": len(pols),
        "rules": [
            {"id": r["id"], "confidence": r.get("confidence"),
             "n_matched": s["matched"], "n_hit_any": s["hit_any"],
             "pct_hit_any": round(pct, 2),
             "per_domain": {d: {"n": s["per_domain"].get(d, 0),
                                "pct": round(100 * s["per_domain"].get(d, 0) / s["matched"], 2)
                                if s["matched"] else 0}
                            for d in r["domains"]},
             "examples_miss": s["examples_miss"]}
            for r, s, m, h, pct in rows
        ],
    }
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
