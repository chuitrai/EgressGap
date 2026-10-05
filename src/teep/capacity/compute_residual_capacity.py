#!/usr/bin/env python3
"""
compute_residual_capacity.py - Task 3a: metric CHINH cua T1 (residual
exfiltration capacity), chay tren TOAN BO corpus policy, khong phu thuoc
S1 hay R_exec.

DINH NGHIA (theo dung de cuong goc TEEP, Stage 2 cua project instructions):
    Voi MOI policy CO CUONG CHE (egress_policy: block, khong bi template hoa,
    co it nhat 1 host khai bao) trong data/policies_ci.jsonl:
      I = tap host khai bao (declared) cua policy do
      Voi MOI host h trong I, phan loai h vao 0..4 KENH ro ri con lai, dung
      LAI bang tham chieu S2 da xay san (measurement/s2_reference.json,
      build boi build_s2_reference.py, DA PHU TOAN BO host cua chinh quan
      the nay - xem build_s2_reference.py doc "--policies data/policies_ci.jsonl"):

        (a) shared-CDN/cloud-IP (SNI/Host-spoofable)
            <=> s2[h]["flags"] co "shared_ip" (n_cotenants >= 1: h dung
                chung it nhat 1 IP voi domain khac trong Tranco top-100k)
        (b) user-content-platform co write API (LOTS)
            <=> s2[h]["flags"] co "lots" (h khop 1 hau to trong lots.json -
                danh sach ha tang tung bi dung lam LOTS/LOLC2)
        (c) DoH-resolver-reachable
            <=> s2[h]["flags"] co "doh_resolver" (h CHINH LA 1 resolver DoH
                cong khai da biet - vd dns.google - nen ban than viec cho
                phep h da mo duong DoH tunnel, dung PoC cua Batham trich
                trong de cuong)
        (d) wildcard-over-broad
            <=> s2[h]["flags"] co "wildcard" (h viet duoi dang *.x) HOAC
                "open_namespace" (h CHINH LA mot public suffix - PSL lop A -
                nen no la mot NAMESPACE DA THUE BAO, ai cung dang ky duoc
                subdomain ben duoi)

      policy co >=1 kenh ro ri  <=>  ton tai h trong I co >=1 trong 4 co (a-d)

    BAO CAO:
      - % policy co >=1 kenh ro ri con lai (headline)
      - ty le xuat hien tung kenh rieng le (prevalence, KHONG loai tru nhau -
        1 host/policy co the vua la (a) vua la (d) cung luc)
      - phan phoi "so LOAI kenh phan biet" moi policy (0,1,2,3,4)

    QUAN THE (population, theo dung quyet dinh cua Bao 2026-09-12): moi
    DONG POLICY rieng le trong policies_ci.jsonl (KHONG gop theo repo) -
    giong don vi phan tich "policy artifact" ma de cuong T1 dung tu dau
    ("the policy artifact (the allowlist as written by a defender)").

    KHONG CAN S1 hay R_exec: day la diem manh cua metric nay - no KHONG
    phu thuoc vao chat luong static-rule-matching (S1, da xac nhan on dinh)
    lan chat luong R_exec (dang PROVISIONAL - xem memory note "R_exec 45.9%
    wrong-job": ~45.9% corpus bi fetch nham job/workflow, dang cho Bao chay
    script sua tren may rieng). Vi vay day nen la con so headline chinh cua
    T1, KHONG phai Task 2 (over-declaration vs R_exec).

SENSITIVITY (bat buoc di kem, theo dung van hoa "khong bao gio 1 con so
duy nhat" cua du an - xem Task 2 median-of-ratios vs ratio-of-medians,
Task 4 same-fold-baseline): ngoai con so CHINH (moi dong policy la 1 don
vi, ke ca trung lap tap host - vi day la quan the THAT, khong phai mau chon
de kiem tra tay), tinh THEM 1 phien ban DEDUP theo (repo, frozenset(hosts))
- giong ky thuat sample20.py dung de tranh dem 1 tap host bot-template lap
lai N lan nhu N quan sat doc lap. Neu 2 con so lech nhieu -> ket luan headline
can neu ro bi chi phoi boi duplicate/bot-template toi muc nao.

INPUT
    data/policies_ci.jsonl          (moi dong = 1 policy: repo, path, job,
                                      step_idx, enforced, uses_templating,
                                      hosts, n_unique_hosts, ...)
    measurement/s2_reference.json   (host -> flags, DA XAY SAN, full corpus)

OUTPUT
    measurement/residual_capacity.json

CHAY
    uv run python measurement/compute_residual_capacity.py
"""
from teep import paths as _P
import argparse
import collections
import json
import statistics as st
from pathlib import Path

from teep.static.build_learnable_bucket import is_domain_like

CHANNELS = ["shared_ip", "lots", "doh_resolver", "wildcard_or_open_ns"]

# v1.1 (2026-09-13, sau lan chay dau tren toan corpus): 2 phat hien can sua/them
# tu chinh output that:
#
# (1) 485/3186 (15%) host phan biet trong policies_ci.jsonl["hosts"] la RAC
#     ("${{", "&&", "(`domain", "(agent", "(first"...) - CUNG loai bug voi
#     is_domain_like() da sua o build_learnable_bucket.py (Task 4), nhung o
#     day chua ap dung filter do. Sua: loc hosts qua is_domain_like() truoc
#     khi phan loai kenh - dung LAI ham da co, khong viet lai.
#
# (2) Kenh (b) LOTS bi 1 domain THONG TRI: "github.com" (VA cac subdomain/
#     domain lien quan nhu raw.githubusercontent.com, objects.githubuser
#     content.com...) tu ban than la 1 muc trong lots.json (GitHub la vi du
#     LOTS/LOLC2 kinh dien - chinh de cuong T1 cung liet ke GitHub dau tien).
#     NHUNG github.com/api.github.com/codeload.github.com gan nhu BAT BUOC
#     phai co trong MOI policy GitHub Actions (checkout, actions runtime) -
#     nen prevalence ~93% cua kenh LOTS mot phan lon la do 1 phu thuoc
#     KHONG THE TRANH, khong phai do developer tu y khai bao them. Neu bao
#     cao "93% policy co LOTS" ma khong tach bach, reviewer se bat bo ngay
#     ("dung nhien ai cung can github.com"). Sua: tach kenh LOTS thanh
#     lots_mandatory_github (khop *.github.com hoac *.githubusercontent.com)
#     vs lots_discretionary (tat ca LOTS match KHAC - pastebin.com,
#     drive.google.com, dropbox.com, mega.nz, wetransfer.com, slack.com...) -
#     ve TAT ca kenh residual van tinh ca 2, nhung bao cao rieng ty le
#     "co it nhat 1 LOTS KHONG-phai-github" - day moi la con so "developer
#     tu them rui ro" that su dang tin, khong bi phu thuoc cau truc che mo.


def is_github_mandatory_lots(host, lots_match):
    """True neu match LOTS nay la ha tang GitHub gan nhu bat buoc phai khai
    bao de chay duoc GitHub Actions (checkout/artifact/runtime), KHONG phai
    developer tu chon them."""
    if not lots_match:
        return False
    h = host.lower()
    if h == "github.com" or h.endswith(".github.com"):
        return True
    if h == "githubusercontent.com" or h.endswith(".githubusercontent.com"):
        return True
    return False


def host_channels(h, s2):
    """Tra (set cac kenh a-d khop host h, co trong s2 khong).

    Kenh 'lots' duoc tach them thanh 'lots' (tong, giu tuong thich nguoc)
    VA 1 trong 2 nhan phu 'lots_mandatory_github'/'lots_discretionary' de
    phan tich rieng (xem ghi chu v1.1 o tren)."""
    info = s2.get(h)
    if info is None:
        return set(), False
    flags = set(info.get("flags") or [])
    ch = set()
    if "shared_ip" in flags:
        ch.add("shared_ip")
    if "lots" in flags:
        ch.add("lots")
        if is_github_mandatory_lots(h, info.get("lots_match")):
            ch.add("lots_mandatory_github")
        else:
            ch.add("lots_discretionary")
    if "doh_resolver" in flags:
        ch.add("doh_resolver")
    if "wildcard" in flags or "open_namespace" in flags:
        ch.add("wildcard_or_open_ns")
    return ch, True


def load_policies(path):
    """Doc policies_ci.jsonl, ap dung DUNG bo loc quan the ma
    build_s2_reference.py/sample20.py da dung (enforced && khong template
    hoa && co it nhat 1 host)."""
    out = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            hosts = sorted({h.lower() for h in (r.get("hosts") or [])
                            if is_domain_like(h.lower())})
            if not hosts:
                continue
            out.append({
                "repo": r["repo"], "path": r.get("path"), "job": r.get("job"),
                "step_idx": r.get("step_idx"), "hosts": hosts,
                "n_hosts": len(hosts), "has_wildcard": r.get("n_wildcards", 0) > 0,
                "line_no": i,
            })
    return out


EXTRA_LOTS_CHANNELS = ["lots_mandatory_github", "lots_discretionary"]


def analyze(policies, s2, label):
    """Tra dict thong ke tong hop cho 1 danh sach policy (raw hoac dedup)."""
    n = len(policies)
    n_with_residual = 0
    n_with_residual_strict = 0
    channel_prevalence = collections.Counter()  # so POLICY co >=1 host kenh do
    n_channel_types_dist = collections.Counter()  # 0..4 loai KENH CHINH (a-d) / policy
    unmatched_hosts = set()
    matched_hosts = set()
    per_policy_rows = []

    for p in policies:
        policy_channels = set()  # co ca lots_mandatory_github/lots_discretionary
        for h in p["hosts"]:
            ch, found = host_channels(h, s2)
            if found:
                matched_hosts.add(h)
            else:
                unmatched_hosts.add(h)
            policy_channels |= ch

        has_residual = len(policy_channels) > 0
        if has_residual:
            n_with_residual += 1

        # BAN "strict": loai bo lots NEU chi den tu ha tang GitHub bat buoc
        # (khong co lots_discretionary nao khac) - xem ghi chu v1.1 o dau file.
        main_channels_only = policy_channels & set(CHANNELS)  # chi 4 kenh a-d
        strict_channels = set(main_channels_only)
        if "lots" in strict_channels and "lots_discretionary" not in policy_channels:
            strict_channels.discard("lots")  # lots o day CHI la github bat buoc
        has_residual_strict = len(strict_channels) > 0
        if has_residual_strict:
            n_with_residual_strict += 1

        for c in policy_channels:
            channel_prevalence[c] += 1
        n_channel_types_dist[len(main_channels_only)] += 1  # dua tren 4 kenh chinh
        per_policy_rows.append({
            "repo": p["repo"], "path": p["path"], "job": p["job"],
            "n_hosts": p["n_hosts"], "channels": sorted(policy_channels),
            "has_residual": has_residual,
            "has_residual_strict": has_residual_strict,
        })

    print(f"\n{'='*78}\n{label}  (n = {n} policy)\n{'='*78}")
    if n == 0:
        print("  (khong co policy nao)")
        return None
    pct_residual = 100 * n_with_residual / n
    pct_residual_strict = 100 * n_with_residual_strict / n
    print(f"  Policy co >=1 kenh ro ri con lai (LENIENT, tinh ca LOTS-github bat buoc):")
    print(f"    {n_with_residual}/{n}  ({pct_residual:.1f}%)")
    print(f"  Policy co >=1 kenh ro ri con lai (STRICT, LOAI TRU LOTS-github-bat-buoc-don-thuan):")
    print(f"    {n_with_residual_strict}/{n}  ({pct_residual_strict:.1f}%)  <-- so nay moi dang tin la")
    print(f"    'developer tu them rui ro', khong bi phu thuoc GitHub Actions runtime che mo")
    print(f"  --- prevalence tung kenh CHINH (khong loai tru nhau) ---")
    for c in CHANNELS:
        cnt = channel_prevalence.get(c, 0)
        print(f"    {c:22s} {cnt:6d} policy  ({100*cnt/n:5.1f}%)")
    print(f"  --- tach rieng kenh LOTS: bat buoc (github) vs tu chon (khac) ---")
    for c in EXTRA_LOTS_CHANNELS:
        cnt = channel_prevalence.get(c, 0)
        print(f"    {c:22s} {cnt:6d} policy  ({100*cnt/n:5.1f}%)")
    print(f"  --- phan phoi so LOAI kenh CHINH (a-d) phan biet / policy ---")
    for k in sorted(n_channel_types_dist):
        cnt = n_channel_types_dist[k]
        print(f"    {k} loai kenh : {cnt:6d} policy  ({100*cnt/n:5.1f}%)")
    n_host_total = len(matched_hosts) + len(unmatched_hosts)
    if n_host_total:
        print(f"  --- do phu S2 ---")
        print(f"    host khop S2     : {len(matched_hosts)}/{n_host_total} "
              f"({100*len(matched_hosts)/n_host_total:.1f}%)")
        if unmatched_hosts:
            print(f"    host KHONG khop S2 (tinh la 'khong xac nhan duoc rui ro', "
                  f"KHONG phai 'an toan'): {len(unmatched_hosts)} - vd: "
                  f"{sorted(unmatched_hosts)[:5]}")

    return {
        "label": label, "n_policy": n,
        "n_with_residual": n_with_residual,
        "pct_with_residual": round(pct_residual, 2),
        "n_with_residual_strict": n_with_residual_strict,
        "pct_with_residual_strict": round(pct_residual_strict, 2),
        "channel_prevalence": {c: channel_prevalence.get(c, 0) for c in CHANNELS},
        "channel_prevalence_pct": {c: round(100*channel_prevalence.get(c, 0)/n, 2) for c in CHANNELS},
        "lots_split": {c: channel_prevalence.get(c, 0) for c in EXTRA_LOTS_CHANNELS},
        "lots_split_pct": {c: round(100*channel_prevalence.get(c, 0)/n, 2) for c in EXTRA_LOTS_CHANNELS},
        "n_channel_types_dist": dict(sorted(n_channel_types_dist.items())),
        "n_host_matched_s2": len(matched_hosts),
        "n_host_unmatched_s2": len(unmatched_hosts),
        "unmatched_host_sample": sorted(unmatched_hosts)[:20],
        "rows": per_policy_rows,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/residual_capacity.json")))
    ap.add_argument("--selected-repos", default=str(_P.data("measurement/taskb_selected_repos.json")),
                     help="dung de doi chieu quan the (B2 audit): 7137 policy den tu bao nhieu repo, "
                          "bao nhieu trong so do nam trong 698 repo da loc cua Task 1/2")
    a = ap.parse_args()

    s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]
    policies = load_policies(a.policies)
    print(f"[*] {len(policies)} policy co cuong che, khong template hoa, co host "
          f"(tu {a.policies})")
    print(f"[*] S2: {len(s2)} host duoc danh dau (tu {a.s2})")

    # --- B2 (audit 2026-09-13): quan the CUA TASK 3 la POLICY, khac voi Task 1/2
    # (REPO, da loc con 698). Can bao cao RO so repo phan biet dang sau 7137
    # policy nay, va so sanh voi 698 de biet Task 3 rong hon hay hep hon.
    n_repo_distinct = len({p["repo"] for p in policies})
    repo_698 = set()
    if Path(a.selected_repos).exists():
        sel = json.loads(Path(a.selected_repos).read_text(encoding="utf-8"))["selected"]
        repo_698 = {c["repo"] for c in sel}
    repos_in_policies = {p["repo"] for p in policies}
    n_overlap = len(repos_in_policies & repo_698)
    n_outside_698 = len(repos_in_policies - repo_698)
    print(f"\n[*] QUAN THE (B2): {len(policies)} policy den tu {n_repo_distinct} repo phan biet.")
    if repo_698:
        print(f"    Trong do {n_overlap}/{n_repo_distinct} repo NAM TRONG 698 repo da loc cua "
              f"Task 1/2 (co R_exec, pushed_at gan day, khong trung allowlist).")
        print(f"    {n_outside_698}/{n_repo_distinct} repo KHONG nam trong 698 - Task 3 chay tren "
              f"quan the RONG HON Task 1/2 (toan bo harvest co policy cuong che, khong loc theo "
              f"R_exec/pushed_at/dedup-allowlist) - HOP LE nhung PHAI neu ro trong Method, khong duoc "
              f"ngam hieu Task 3 va Task 1/2 dung cung 1 quan the repo.")

    # --- CHINH: moi dong policy la 1 don vi (bao gom ca trung lap tap host) ---
    main_stats = analyze(policies, s2, "CHINH - moi dong policy (quan the that, ke ca trung lap)")

    # --- PHU: dedup theo (repo, frozenset(hosts)) - sensitivity ---
    seen = set()
    dedup_policies = []
    for p in policies:
        key = (p["repo"], frozenset(p["hosts"]))
        if key in seen:
            continue
        seen.add(key)
        dedup_policies.append(p)
    dedup_stats = analyze(dedup_policies, s2,
                           "PHU (sensitivity) - dedup theo (repo, tap host) - tranh dem bot-template lap")

    if main_stats and dedup_stats:
        diff = abs(main_stats["pct_with_residual"] - dedup_stats["pct_with_residual"])
        diff_strict = abs(main_stats["pct_with_residual_strict"] - dedup_stats["pct_with_residual_strict"])
        print(f"\n{'='*78}\nSO SANH CHINH vs DEDUP\n{'='*78}")
        print(f"  LENIENT  CHINH : {main_stats['pct_with_residual']:.1f}%  "
              f"DEDUP : {dedup_stats['pct_with_residual']:.1f}%  (lech {diff:.1f} diem %)")
        print(f"  STRICT   CHINH : {main_stats['pct_with_residual_strict']:.1f}%  "
              f"DEDUP : {dedup_stats['pct_with_residual_strict']:.1f}%  (lech {diff_strict:.1f} diem %)")

    out = {
        "population": {
            "n_policy": len(policies), "n_repo_distinct": n_repo_distinct,
            "n_repo_in_698_selected": n_overlap, "n_repo_outside_698_selected": n_outside_698,
        },
        "main": {k: v for k, v in (main_stats or {}).items() if k != "rows"},
        "dedup": {k: v for k, v in (dedup_stats or {}).items() if k != "rows"},
        "main_rows": main_stats["rows"] if main_stats else [],
        "dedup_rows": dedup_stats["rows"] if dedup_stats else [],
    }
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")


if __name__ == "__main__":
    main()
