#!/usr/bin/env python3
"""
tighten_tree.py - Siet allowlist bang CAY PHAN CAP TEN MIEN (domain tree).

Y TUONG (khac tighten_policy.py):
    tighten_policy = giu/bo NGUYEN mot host.
    tighten_tree   = voi WILDCARD, khong bo ca cum, ma SIET xuong cac LA
                     cu the that su duoc quan sat (S3) / xuat hien that.

    Vi du:
        allowlist:  *.githubusercontent.com     (mo ca namespace, expansion khong lo)
        quan sat:   objects.githubusercontent.com, raw.githubusercontent.com
        -> siet thanh dung 2 la do. Namespace 10^6 -> 2 dich.

    Day chinh la "general condition, hep hon" (Restricter): giu cau truc cay,
    ha xuong node hep nhat con phu du lieu quan sat.

CACH LAM
    1. Xay cay hau to (reverse-label) tu tap la quan sat duoc (S3 hoac corpus).
    2. Voi moi entry khai bao:
         - la cu the, co bang chung  -> giu
         - wildcard *.X -> thay bang cac la quan sat duoc DUOI X
                           (khong co la nao -> bo + danh dau, KHONG giu wildcard)
    3. Do expansion truoc/sau: open-namespace (coi ~10^6) -> so la thuc.

HAN CHE (ghi Limitations):
    - Chi tot khi tap la quan sat DAY DU. Thieu la hop le -> siet qua tay,
      pha build. Vi vay khi build fail vi la bi bo -> DUNG, bao nguoi.
    - Voi la KHONG quan sat duoc lan nao, khong the biet no can hay khong ->
      day la dong lai luon can S3, khong tu dong hoa het duoc.

CHAY (demo dung corpus lam nguon la thay cho S3)
    python measurement/tighten_tree.py --leaves-from corpus
    python measurement/tighten_tree.py --leaves-from measurement/s3_captured
"""
from teep import paths as _P
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

DATA = _P.data("data")
OPEN_NS_SIZE = 10 ** 6      # coi namespace mo la "vo han" de so sanh expansion


def wildcard_suffix(w):
    return re.sub(r"^[^.]*\*[^.]*\.", "", w.lower().lstrip("*").lstrip("."))


def under(host, suffix):
    host = host.lower()
    return host == suffix or host.endswith("." + suffix)


def collect_leaves_from_corpus():
    """Tat ca host CU THE (khong wildcard) tung xuat hien trong policy that."""
    leaves = set()
    with open(DATA / "policies_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            for h in r.get("hosts") or []:
                h = h.lower()
                if "*" not in h and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", h):
                    leaves.add(h)
    return leaves


def collect_leaves_from_s3(d):
    """Gom moi r_*.json / *.json trong thu muc S3 thanh tap la quan sat."""
    leaves = set()
    p = Path(d)
    files = [p] if p.is_file() else list(p.glob("*.json"))
    for fp in files:
        try:
            j = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            continue
        for h in j.get("required_set", []):
            leaves.add(h.lower().split(":")[0])
    return leaves


def tighten_tree(declared, observed_leaves, s1_domains=None):
    """Tra (new_entries, actions) — actions ghi lai da lam gi voi tung entry."""
    s1_domains = s1_domains or set()
    new_entries, actions = [], []
    for h in declared:
        hl = h.lower().split(":")[0]
        if "*" in hl:
            suf = wildcard_suffix(hl)
            leaves = sorted(l for l in observed_leaves if under(l, suf))
            if leaves:
                new_entries.extend(leaves)
                actions.append((h, "wildcard->leaves", leaves))
            else:
                actions.append((h, "wildcard-drop(khong quan sat)", []))
        else:
            # la cu the: giu neu co bang chung (S1 hoac quan sat), else danh dau
            keep = (hl in observed_leaves) or any(
                d.lower() == hl for d in s1_domains)
            if keep:
                new_entries.append(hl)
                actions.append((h, "keep", [hl]))
            else:
                actions.append((h, "drop(khong bang chung)", []))
    return sorted(set(new_entries)), actions


def expansion_estimate(entries):
    """Uoc luong |E|/|I| kieu cu phap: wildcard mo = 10^6, con lai = 1 moi entry."""
    if not entries:
        return 0, 0
    E = 0
    for e in entries:
        E += OPEN_NS_SIZE if "*" in e else 1
    return E, round(E / len(entries), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=str(_P.data("measurement/sample20.json")))
    ap.add_argument("--leaves-from", default="corpus",
                    help="'corpus' hoac duong dan thu muc S3")
    ap.add_argument("--out", default=str(_P.data("measurement/tree_tighten.json")))
    a = ap.parse_args()

    if a.leaves_from == "corpus":
        leaves = collect_leaves_from_corpus()
        src = "corpus (proxy cho S3)"
    else:
        leaves = collect_leaves_from_s3(a.leaves_from)
        src = a.leaves_from
    print(f"[*] {len(leaves):,} la quan sat tu: {src}")

    sample = json.loads(Path(a.sample).read_text(encoding="utf-8"))["policies"]

    rows = []
    for p in sample:
        declared = [h.lower() for h in p["hosts"]]
        has_wc = any("*" in h for h in declared)
        if not has_wc:
            continue          # phuong phap cay chi co y nghia voi wildcard
        new_entries, actions = tighten_tree(declared, leaves)
        E0, x0 = expansion_estimate(declared)
        E1, x1 = expansion_estimate(new_entries)
        rows.append({
            "id": p["sample_id"], "repo": p["repo"],
            "declared": declared, "n_declared": len(declared),
            "tightened": new_entries, "n_tightened": len(new_entries),
            "expansion_before": x0, "expansion_after": x1,
            "actions": [{"entry": e, "op": op, "result": r} for e, op, r in actions],
        })

    Path(a.out).write_text(json.dumps({"leaves_source": src, "n": len(rows),
                                       "policies": rows}, indent=1,
                                      ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 92)
    print("SIET BANG CAY - chi cac policy CO WILDCARD")
    print("=" * 92)
    print(f"{'id':4s} {'repo':30s} {'|I|':>4s} {'|I_cay|':>7s} "
          f"{'exp_truoc':>10s} {'exp_sau':>9s}")
    print("-" * 92)
    for r in rows:
        print(f"{r['id']:4s} {r['repo'][:30]:30s} {r['n_declared']:4d} "
              f"{r['n_tightened']:7d} {r['expansion_before']:10.0f} {r['expansion_after']:9.1f}")

    # vi du chi tiet 1 policy co wildcard open-namespace
    print("\n" + "=" * 92)
    print("VI DU CHI TIET: wildcard duoc ha xuong cac la quan sat")
    print("=" * 92)
    shown = 0
    for r in rows:
        for act in r["actions"]:
            if act["op"] == "wildcard->leaves":
                print(f"  [{r['id']}] {act['entry']}")
                print(f"        -> {len(act['result'])} la: {act['result'][:6]}"
                      f"{' ...' if len(act['result'])>6 else ''}")
                shown += 1
        if shown >= 6:
            break

    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
