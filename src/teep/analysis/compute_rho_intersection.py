#!/usr/bin/env python3
r"""
compute_rho_intersection.py - "Phuong an dat" cho phan hoi peer-review C1/A1.

CAU HOI PEER-REVIEW (R1, xac nhan boi R2 la "gap hinh thuc thuc su"):
    Metric headline 66.6%/36.9% dinh nghia la E(I)\rho (reachable TRU required),
    nhung khi TINH thi chi dem "policy co >=1 declared host mang channel (a-d)",
    RUI tru phan platform bat buoc - KHONG BAO GIO tru rho. Nen mot host nhu
    pypi.org (build THAT SU can) van bi tinh vao vi no co co-tenancy. R1 doc do
    la "dem required nhu residual".

    Phuong an RE (da lam): doi ten metric -> "reachability expansion", bo cum
    "beyond what the build needs".
    Phuong an DAT (script nay): GIAO tap host-bi-flag voi rho_hat = S1 U R_exec,
    dem bao nhieu host bi flag ma KHONG nam trong required set -> bien tranh cai
    framing thanh MOT CON SO.

DINH NGHIA CHINH XAC:
    rho_hat(P) = S1(P) U R_exec(repo(P))    (uoc luong CAN DUOI cua rho)
        S1(P)         = static_domains(workflow_text, rules)  (nhu tighten_full_corpus)
        R_exec(repo)  = domain WORKLOAD quan sat that (taskb_step2_urls_v2.json)
    Mot declared host h duoc coi la "required" <=> h duoc S1 justify HOAC h thuoc
    R_exec  <=> h nam trong 'kept' cua tighten(I, S1, s3=R_exec). (Dung LAI dung
    ham tighten()/host_matches() cua tighten_policy.py - KHONG viet lai logic.)

    flagged(P)              = { h in I : strict_flag(h) }   (host mang >=1 kenh a-d
                              theo dung ban STRICT cua compute_residual_capacity.py:
                              shared_ip / wildcard_or_open_ns / doh_resolver luon tinh;
                              lots CHI tinh neu la lots_discretionary, KHONG phai
                              github-bat-buoc)
    beyond_required(P)      = { h in flagged(P) : h KHONG required }
                            = flagged(P) \ rho_hat(P)

    -> METRIC MOI (dung E(I)\rho hon):
       % policy co >=1 host VUA mang channel VUA khong nam trong required set.
       Day la "residual capacity tren dich build KHONG he can" - phan AVOIDABLE.
       Phan con lai (flagged nhung required, vd pypi.org) la co-tenancy CAU TRUC
       tren dich that su can - dung cai R1 noi, va ta tach bach ra thay vi choi.

HUONG THIEN LECH (phai neu ro trong paper):
    rho_hat = S1 U R_exec la CAN DUOI cua rho that (ca hai deu under-count cai build
    can). Nen {h khong thuoc rho_hat} ⊇ {h khong thuoc rho} -> "beyond_required"
    dem DU (mot so host thuc ra required nhung S1/R_exec bo sot). Vi vay:
      % beyond_required la CAN TREN cua ty le residual-tren-dich-khong-can.
    Nguoc lai, phan "flagged VA required" la VUNG CHAC (S1/R_exec noi can thi dung
    la can) -> day la can duoi cua "co-tenancy cau truc tren dich that su can".

LUU Y KHAI NIEM (R2 chi ra, phai ghi vao Limitations):
    Residual capacity THUC ra la cac CO-TENANT with toi duoc qua h, KHONG phai
    ban than h. Mot h REQUIRED (pypi.org) van mo duong toi co-tenant ngoai rho.
    Nen script nay CO TINH BAO THU: no chi dem "vehicle khong-can" (double fault:
    channel + khong required), KHONG dem co-tenant cua vehicle required. Vi vay
    con so beyond_required la mot LAT CAT chat (avoidable residual), con phan
    cau truc van ton tai bat ke.

BA QUAN THE BAO CAO:
    (1) FULL 7137 policy, rho_hat = S1-only (R_exec = rong cho repo khong co) -
        rho_hat yeu nhat -> beyond_required cao nhat (can tren long nhat).
    (2) SUBSET co R_exec, rho_hat = S1 U R_exec - rho_hat manh nhat -> con so
        dang tin nhat de trich vao paper.
    (3) Sanity: % policy co >=1 flagged (khong giao rho) PHAI khop
        residual_capacity.json pct_with_residual_strict (66.58%) - neu lech,
        co bug trong ban sao strict_flag() cua script nay.

INPUT  (giong compute_would_break.py + compute_residual_capacity.py)
    data/policies_ci.jsonl
    measurement/s2_reference.json
    measurement/taskb_run_data/taskb_step2_urls_v2.json
    data/files_ci.jsonl, data/files/*
    measurement/static_rules.json
OUTPUT
    measurement/rho_intersection_result.json
CHAY
    uv run python measurement/compute_rho_intersection.py
"""
from teep import paths as _P
import argparse
import json
from pathlib import Path

from teep.capacity.tighten_policy import compile_rules, static_domains, tighten, host_matches
from teep.capacity.compute_residual_capacity import load_policies, host_channels

DATA = _P.data("data")
STRICT_MAIN = {"shared_ip", "wildcard_or_open_ns", "doh_resolver"}


def strict_flag(channels):
    """host mang >=1 kenh residual theo ban STRICT (khop dung logic
    compute_residual_capacity.analyze: 3 kenh chinh luon tinh; lots CHI tinh
    neu discretionary, KHONG phai github bat buoc)."""
    if channels & STRICT_MAIN:
        return True
    if "lots_discretionary" in channels:
        return True
    return False


def load_rexec_workload(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for repo, entries in raw.items():
        hosts = {e["domain"].lower() for e in entries if e.get("classification") == "WORKLOAD"}
        if hosts:
            out[repo] = hosts
    return out


def load_blob_index(path):
    idx = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            idx[(d["repo"], d["path"])] = d["blob"]
    return idx


def s1_for_policy(policy, blob_of, rules, cache):
    """S1(P) = static_domains(workflow_text). Cache theo blob de khong doc lai.
    Tra set domain S1 du doan, hoac None neu khong doc duoc blob."""
    key = (policy["repo"], policy["path"])
    if key in cache:
        return cache[key]
    blob = blob_of.get(key)
    s1 = None
    if blob:
        fp = DATA / "files" / blob
        try:
            txt = fp.read_text(encoding="utf-8", errors="replace")
            s1, _prov, _m = static_domains(txt, rules)
        except OSError:
            s1 = None
    cache[key] = s1
    return s1


def required_set_membership(hosts, s1_domains, rexec_hosts):
    """Tra set host trong 'hosts' duoc coi la REQUIRED (thuoc rho_hat = S1 U R_exec).
    Dung LAI tighten(): 'kept' = host duoc S1 justify hoac thuoc s3 (=R_exec)."""
    kept, _dropped, _reason = tighten(hosts, s1_domains or set(), s3_hosts=rexec_hosts)
    return {h.lower() for h in kept}


def analyze(policies, s2, blob_of, rules, rexec, use_rexec, label):
    s1_cache = {}
    n = 0
    n_flagged_policy = 0                 # >=1 host flagged (khong giao rho) -> sanity ~66.6%
    n_beyond_required_policy = 0         # >=1 host flagged VA khong required -> METRIC MOI
    n_only_structural_policy = 0         # co flagged nhung TAT CA flagged deu required
    n_no_s1 = 0
    # dem theo HOST (tren toan quan the)
    host_flagged_total = 0
    host_flagged_required = 0            # flagged nhung required (co-tenancy cau truc)
    host_flagged_beyond = 0              # flagged va khong required (avoidable)
    rows = []

    for p in policies:
        n += 1
        s1 = s1_for_policy(p, blob_of, rules, s1_cache)
        if s1 is None:
            n_no_s1 += 1
        R = rexec.get(p["repo"], set()) if use_rexec else set()
        required = required_set_membership(p["hosts"], s1, R)

        flagged_here = []
        beyond_here = []
        for h in p["hosts"]:
            ch, _found = host_channels(h, s2)
            if not strict_flag(ch):
                continue
            flagged_here.append(h)
            host_flagged_total += 1
            if h.lower() in required:
                host_flagged_required += 1
            else:
                host_flagged_beyond += 1
                beyond_here.append(h)

        if flagged_here:
            n_flagged_policy += 1
            if beyond_here:
                n_beyond_required_policy += 1
            else:
                n_only_structural_policy += 1

        if beyond_here:
            rows.append({
                "repo": p["repo"], "path": p["path"], "job": p["job"],
                "n_hosts": p["n_hosts"],
                "flagged": sorted(flagged_here),
                "beyond_required": sorted(beyond_here),
                "s1_available": s1 is not None,
                "rexec_available": bool(R),
            })

    def pc(x):
        return round(100 * x / n, 2) if n else None

    print(f"\n{'='*78}\n{label}  (n = {n} policy)\n{'='*78}")
    print(f"  [sanity] policy co >=1 host flagged (KHONG giao rho): "
          f"{n_flagged_policy}/{n} ({pc(n_flagged_policy)}%)  "
          f"<-- phai ~66.58% (residual_capacity strict) neu strict_flag() dung")
    print(f"  [METRIC MOI E(I)\\rho] policy co >=1 host flagged VA khong required: "
          f"{n_beyond_required_policy}/{n} ({pc(n_beyond_required_policy)}%)")
    print(f"  policy co flagged nhung TAT CA deu required (co-tenancy cau truc thuan): "
          f"{n_only_structural_policy}/{n} ({pc(n_only_structural_policy)}%)")
    if n_no_s1:
        print(f"  [!] {n_no_s1} policy khong doc duoc blob -> S1=None (chi dua vao R_exec"
              f"{' neu co' if use_rexec else '; R_exec TAT'} de xet required)")
    print(f"  --- theo HOST ---")
    print(f"    host flagged tong        : {host_flagged_total}")
    if host_flagged_total:
        print(f"    trong do REQUIRED (co-tenancy cau truc tren dich can): "
              f"{host_flagged_required} ({100*host_flagged_required/host_flagged_total:.1f}%)")
        print(f"    trong do BEYOND required (avoidable, dung E(I)\\rho hon): "
              f"{host_flagged_beyond} ({100*host_flagged_beyond/host_flagged_total:.1f}%)")

    return {
        "label": label, "n_policy": n,
        "n_flagged_policy": n_flagged_policy, "pct_flagged_policy": pc(n_flagged_policy),
        "n_beyond_required_policy": n_beyond_required_policy,
        "pct_beyond_required_policy": pc(n_beyond_required_policy),
        "n_only_structural_policy": n_only_structural_policy,
        "pct_only_structural_policy": pc(n_only_structural_policy),
        "host_flagged_total": host_flagged_total,
        "host_flagged_required": host_flagged_required,
        "host_flagged_beyond": host_flagged_beyond,
        "n_policy_no_s1_blob": n_no_s1,
        "rows_beyond_sample": rows[:40],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--s2", default=str(_P.data("measurement/s2_reference.json")))
    ap.add_argument("--rexec", default=str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json")))
    ap.add_argument("--files-index", default=str(_P.data("data/files_ci.jsonl")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/rho_intersection_result.json")))
    a = ap.parse_args()

    s2 = json.loads(Path(a.s2).read_text(encoding="utf-8"))["hosts"]
    policies = load_policies(a.policies)
    rules = compile_rules(a.rules)
    blob_of = load_blob_index(a.files_index)
    rexec = load_rexec_workload(a.rexec)
    print(f"[*] {len(policies)} policy | S2 {len(s2)} host | R_exec {len(rexec)} repo")

    # (1) FULL corpus, rho_hat = S1-only (can tren long nhat)
    full_s1only = analyze(policies, s2, blob_of, rules, rexec, use_rexec=False,
                          label="(1) FULL 7137 - rho_hat = S1-only (can tren cao nhat)")

    # (2) FULL corpus, rho_hat = S1 U R_exec (repo co R_exec thi manh hon)
    full_both = analyze(policies, s2, blob_of, rules, rexec, use_rexec=True,
                        label="(2) FULL 7137 - rho_hat = S1 U R_exec (repo co R_exec)")

    # (3) SUBSET chi cac policy thuoc repo CO R_exec, rho_hat = S1 U R_exec (dang tin nhat)
    pol_with_rexec = [p for p in policies if p["repo"] in rexec]
    subset_both = analyze(pol_with_rexec, s2, blob_of, rules, rexec, use_rexec=True,
                          label=f"(3) SUBSET co R_exec ({len(pol_with_rexec)} policy) - "
                                f"rho_hat = S1 U R_exec (con so dang tin nhat cho paper)")

    out = {
        "note": "rho_hat = S1 U R_exec la CAN DUOI cua rho -> pct_beyond_required la "
                "CAN TREN cua residual-tren-dich-khong-can. host_flagged_required la "
                "co-tenancy cau truc tren dich that su can (dung diem R1 neu, tach bach "
                "thay vi choi). Metric nay BAO THU: chi dem vehicle khong-can, khong dem "
                "co-tenant cua vehicle required.",
        "full_s1only": full_s1only,
        "full_s1_union_rexec": full_both,
        "subset_with_rexec": subset_both,
    }
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")
    print("\n[!] DOI CHIEU: pct_flagged_policy (bat ky ban nao) PHAI ~66.58% "
          "(residual_capacity.json main.pct_with_residual_strict). Lech -> bug strict_flag().")


if __name__ == "__main__":
    main()
