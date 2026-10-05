#!/usr/bin/env python3
"""
tighten_full_corpus.py - Task 3b: hieu qua "siet" (tighten) allowlist tren
TOAN BO corpus policy, do bang DUNG dinh nghia 4-kenh cua Task 3a
(compute_residual_capacity.py), KHONG chi rieng co-tenancy nhu ban 20-mau
cu (evaluate_policy.py).

Khac voi compute_residual_capacity.py (chi can I + S2, khong can S1),
script nay CAN S1 (static_rules.json) de tinh:
    tightened(I) = { h in I : co bang chung S1 (chua co S3, xem ghi chu
                     duoi) }   (dung lai HAM tighten() trong tighten_policy.py,
                     KHONG viet lai)

Boi vi S1 da duoc xac nhan on dinh (xem parametric_extraction_notes.md),
CON R_exec (S3) dang PROVISIONAL (~45.9% sai job - memory note), script
nay CHUA cam S3 vao (giu s3_hosts=set() giong evaluate_policy.py hien tai)
- giong het quy uoc "khung san sang cam vao" da co san. Khi ban chay xong
script sua R_exec tren may rieng va xac nhan lai % sai job, co the noi lai
S3 vao day (chi can sua ham build_s3_for_policy()).

METRIC MOI POLICY:
    channels_before = hop cac kenh (a-d) tu MOI host trong I (khai bao goc)
    channels_after  = hop cac kenh (a-d) tu MOI host trong I' = tighten(I)
    -> co giam duoc kenh ro ri con lai khong, giam duoc bao nhieu?

    Rieng kenh (a) shared-IP: THEM 1 chi so cu the hon (concrete) la
    |reach(I)| va |reach(I')| (SO DOMAIN thuc te cham toi duoc qua chung
    IP, khong chi la co/khong) - dung lai reach() cua evaluate_policy.py,
    vi day la kenh DUY NHAT co "tap domain thay the cu the" ro rang; (b)/(c)
    la co/khong (domain do CO hay KHONG phai LOTS/DoH), (d) la thuoc tinh
    cua chinh host (wildcard hay khong) - khong co "tap thay the" tuong duong.

    Over-declaration (bang S1, o muc POLICY, KHONG phai repo): ty le host
    khai bao khong co bang chung S1 - day la 1 con so S1-based BO SUNG cho
    Task 2 (von dung R_exec), granularity dung (policy, khop voi Task 3a),
    KHONG phu thuoc R_exec dang provisional - NEN doc con nay song song voi
    Task 2 (R_exec-based) khi 2 con lech nhau.

INPUT
    data/policies_ci.jsonl, data/files_ci.jsonl, data/files/*
    measurement/static_rules.json, measurement/s2_reference.json
    cotenancy/resolved.json, tranco/resolved_top100000.jsonl (co-tenancy, tuy chon)

OUTPUT
    measurement/tighten_full_corpus.json

CHAY
    uv run python measurement/tighten_full_corpus.py
"""
from teep import paths as _P
import argparse
import collections
import json
import statistics as st
from pathlib import Path

from teep.capacity.tighten_policy import compile_rules, static_domains, tighten
from teep.capacity.evaluate_policy import build_fanin, reach
from teep.capacity.compute_residual_capacity import load_policies, host_channels, CHANNELS

DATA = _P.data("data")


def strict_channels(ch):
    """Loai 'lots' khoi tap kenh NEU no CHI den tu ha tang GitHub bat buoc
    (khong co lots_discretionary) - xem ghi chu v1.1 trong compute_residual_
    capacity.py. Dung de tach 'giam vi tighten that su bo host thua' khoi
    'giam gia vi khong the nao bo duoc github.com'."""
    out = ch & set(CHANNELS)
    if "lots" in out and "lots_discretionary" not in ch:
        out.discard("lots")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--files-index", default=str(_P.data("data/files_ci.jsonl")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    ap.add_argument("--resolved", default=str(_P.data("cotenancy/resolved.json")))
    ap.add_argument("--tranco", default=str(_P.data("tranco/resolved_top100000.jsonl")))
    ap.add_argument("--out", default=str(_P.data("measurement/tighten_full_corpus.json")))
    ap.add_argument("--limit", type=int, default=0, help="0 = het corpus; >0 de test nhanh")
    a = ap.parse_args()

    rules = compile_rules(a.rules)
    s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]
    resolved = {}
    ip2dom = collections.defaultdict(set)
    if Path(a.resolved).exists():
        resolved = json.loads(Path(a.resolved).read_text(encoding="utf-8"))
        ip2dom = build_fanin(a.tranco)

    blob_of = {}
    with open(a.files_index, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            blob_of[(d["repo"], d["path"])] = d["blob"]

    policies = load_policies(a.policies)
    if a.limit:
        policies = policies[:a.limit]
    print(f"[*] {len(policies)} policy co cuong che, khong template hoa, co host")
    print(f"[*] S1 rules: {len(rules)}  |  S2: {len(s2)} host  |  "
          f"co-tenancy resolved: {len(resolved)} host  |  fan-in: {len(ip2dom):,} IP")

    rows = []
    n_no_blob, n_unreadable = 0, 0
    for p in policies:
        blob = blob_of.get((p["repo"], p["path"]))
        if not blob:
            n_no_blob += 1
            continue
        fp = DATA / "files" / blob
        try:
            txt = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            n_unreadable += 1
            continue

        declared = p["hosts"]
        s1, prov, matched = static_domains(txt, rules)
        # S3 CHUA cam vao - xem docstring. Khi R_exec het provisional, sua o day.
        s3_hosts = set()
        kept, dropped, reason = tighten(declared, s1, s3_hosts)

        justified_n = len(declared) - len(dropped)
        over_decl_ratio = len(dropped) / len(declared) if declared else 0.0

        ch_before = set()
        for h in declared:
            ch, _ = host_channels(h, s2)
            ch_before |= ch
        ch_after = set()
        for h in kept:
            ch, _ = host_channels(h, s2)
            ch_after |= ch

        sch_before = strict_channels(ch_before)
        sch_after = strict_channels(ch_after)

        row = {
            "repo": p["repo"], "path": p["path"], "job": p["job"],
            "n_declared": len(declared), "n_kept": len(kept), "n_dropped": len(dropped),
            "over_decl_ratio_S1": round(over_decl_ratio, 3),
            "channels_before": sorted(ch_before), "channels_after": sorted(ch_after),
            "has_residual_before": len(ch_before) > 0,
            "has_residual_after": len(ch_after) > 0,
            "has_residual_before_strict": len(sch_before) > 0,
            "has_residual_after_strict": len(sch_after) > 0,
        }
        if resolved:
            rb = reach(declared, resolved, ip2dom)
            ra = reach(kept, resolved, ip2dom)
            row["reach_before"] = len(rb)
            row["reach_after"] = len(ra)
        rows.append(row)

    if n_no_blob or n_unreadable:
        print(f"[!] bo qua {n_no_blob} policy khong tim thay blob, "
              f"{n_unreadable} blob khong doc duoc (encoding/IO)")

    n = len(rows)
    n_res_before = sum(1 for r in rows if r["has_residual_before"])
    n_res_after = sum(1 for r in rows if r["has_residual_after"])
    n_res_before_s = sum(1 for r in rows if r["has_residual_before_strict"])
    n_res_after_s = sum(1 for r in rows if r["has_residual_after_strict"])
    od = [r["over_decl_ratio_S1"] for r in rows if r["n_declared"] > 0]

    print(f"\n{'='*78}\nKET QUA TIGHTENING TOAN CORPUS (n = {n} policy tinh duoc)\n{'='*78}")
    print(f"  [LENIENT, tinh ca LOTS-github bat buoc]")
    print(f"    Policy co >=1 kenh ro ri TRUOC siet : {n_res_before}/{n} ({100*n_res_before/n:.1f}%)")
    print(f"    Policy co >=1 kenh ro ri SAU siet    : {n_res_after}/{n} ({100*n_res_after/n:.1f}%)")
    print(f"    Giam tuyet doi                       : {n_res_before - n_res_after} policy "
          f"({100*(n_res_before-n_res_after)/n:.1f} diem %)")
    print(f"  [STRICT, loai LOTS-github-bat-buoc-don-thuan - phan anh dung 'tighten that su lam duoc gi']")
    print(f"    Policy co >=1 kenh ro ri TRUOC siet : {n_res_before_s}/{n} ({100*n_res_before_s/n:.1f}%)")
    print(f"    Policy co >=1 kenh ro ri SAU siet    : {n_res_after_s}/{n} ({100*n_res_after_s/n:.1f}%)")
    print(f"    Giam tuyet doi                       : {n_res_before_s - n_res_after_s} policy "
          f"({100*(n_res_before_s-n_res_after_s)/n:.1f} diem %)")
    print(f"  Over-declaration theo S1 (policy-level, KHONG R_exec):")
    print(f"    median = {st.median(od)*100:.1f}%   mean = {st.mean(od)*100:.1f}%")

    prev_before = collections.Counter()
    prev_after = collections.Counter()
    for r in rows:
        for c in r["channels_before"]:
            prev_before[c] += 1
        for c in r["channels_after"]:
            prev_after[c] += 1
    print(f"\n  --- prevalence tung kenh: truoc -> sau ---")
    for c in CHANNELS:
        b, af = prev_before.get(c, 0), prev_after.get(c, 0)
        print(f"    {c:22s} {b:6d} ({100*b/n:5.1f}%)  ->  {af:6d} ({100*af/n:5.1f}%)")

    if resolved:
        rb_all = [r["reach_before"] for r in rows if "reach_before" in r]
        ra_all = [r["reach_after"] for r in rows if "reach_after" in r]
        if rb_all:
            print(f"\n  --- kenh (a) co-tenancy, chi tiet SO DOMAIN cham toi duoc ---")
            print(f"    reach truoc siet: median {st.median(rb_all):.0f}  max {max(rb_all)}")
            print(f"    reach sau siet  : median {st.median(ra_all):.0f}  max {max(ra_all)}")

    Path(a.out).write_text(json.dumps({
        "n": n, "n_skipped_no_blob": n_no_blob, "n_skipped_unreadable": n_unreadable,
        "n_residual_before": n_res_before, "n_residual_after": n_res_after,
        "pct_residual_before": round(100*n_res_before/n, 2) if n else None,
        "pct_residual_after": round(100*n_res_after/n, 2) if n else None,
        "n_residual_before_strict": n_res_before_s, "n_residual_after_strict": n_res_after_s,
        "pct_residual_before_strict": round(100*n_res_before_s/n, 2) if n else None,
        "pct_residual_after_strict": round(100*n_res_after_s/n, 2) if n else None,
        "over_decl_S1_median_pct": round(st.median(od)*100, 2) if od else None,
        "over_decl_S1_mean_pct": round(st.mean(od)*100, 2) if od else None,
        "channel_prevalence_before": {c: prev_before.get(c, 0) for c in CHANNELS},
        "channel_prevalence_after": {c: prev_after.get(c, 0) for c in CHANNELS},
        "rows": rows,
    }, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
