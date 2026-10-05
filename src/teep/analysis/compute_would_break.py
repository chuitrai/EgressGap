#!/usr/bin/env python3
"""
compute_would_break.py - "Siet allowlist bang S1 roi, build co con chay khong?"

Cau hoi nay CHUA duoc tra loi o dau trong du an: tighten_full_corpus.py (Task 3b)
do duoc GIAM bao nhieu % kenh ro ri sau khi siet, nhung KHONG kiem tra nguoc lai
lieu ban I' = tighten(I) da bo mat mot host ma build THAT SU can (theo R_exec)
hay chua. Day la cau hoi tu nhien nhat cho 1 bai ve tightening - thieu no la
mot lo hong.

DINH NGHIA
    R_exec(repo) = tap domain WORKLOAD quan sat that (taskb_step2_urls_v2.json,
                   CHI lay classification=="WORKLOAD" - TOOLING da bi loai san
                   boi extract_rlog_v2.py, nen ve R_exec KHONG can loc them).
    I'(repo)     = hop (union) cac host "kept" sau tighten() tren MOI policy
                   (file workflow enforcing) cua repo do. CHUA co san trong
                   tighten_full_corpus.json (file do chi luu n_kept/n_dropped,
                   KHONG luu ten host) nen script nay tu CHAY LAI tighten()
                   - dung LAI dung ham cua tighten_policy.py (S1 + optional S3,
                   S3 de rong giong tighten_full_corpus.py hien tai), KHONG
                   viet lai logic. Vi day la CUNG mot phep tinh voi
                   tighten_full_corpus.py (cung input, cung ham), ket qua
                   n_kept/n_dropped moi policy phai khop file do - neu lech,
                   co bug trong script nay, khong phai trong tighten_full_corpus.py.

    broke(repo)  = { d in R_exec(repo) : khong co host nao trong I'(repo)
                     host_matches (wildcard-aware) d }
    would_break_rate = |{repo : broke(repo) != rong}| / |repo xet duoc|

BA DIEM CAN THAN (theo dung yeu cau cua Bao 2026-09-19):
    (1) CHI xet repo co R_exec dang tin - loai 14% nhieu validity truoc khi
        join. Dung log_validity_audit.json (Task 0), CHI giu category
        "D_declared_block_no_fallback_detected_GOOD" (= "Enforcement genuinely
        applied" trong Table 2 cua report.tex). KHONG dung A/B/C (da biet la
        khong dang tin) LAN E (khong ro).
    (2) host_matches wildcard-aware: LUU Y ten ham dung dung la trong
        tighten_policy.py (KHONG phai policy_scorecard.py nhu ghi chu goc -
        policy_scorecard.py chi co 1 doan inline tuong tu, khong phai ham
        dung chung; ham chinh thuc, da duoc evaluate_policy.py/tighten_policy.py
        dung nhat quan, nam o tighten_policy.host_matches). Import thang tu
        do, KHONG viet lai.
    (3) Loai TOOLING khoi ca hai ve: ve R_exec da loai san (WORKLOAD-only, xem
        tren). Ve I' KHONG loc TOOLING rieng (tighten() giu ca host duoc S1
        tooling-rule chung minh, giong het tighten_full_corpus.py) - nhung
        dieu nay KHONG the tao "broke" gia, vi broke chi xet d thuoc R_exec
        (da la WORKLOAD-only theo dinh nghia) - I' co du thua host tooling
        hay khong khong lam thay doi tap R_exec \\ I'. Ghi ro trong docstring
        nay thay vi loc lai (loc lai se LECH voi tighten_full_corpus.json,
        pha vi du "phai khop nhau" o tren).

QUAN THE: repo phai (a) nam trong 698 repo da chon, (b) category validity =
D (GOOD), (c) co it nhat 1 policy enforcing/khong-template/co-host de tinh
duoc I' (giong dieu kien load_policies cua compute_residual_capacity.py),
(d) R_exec(repo) khac rong (giong dieu kien n=602 cua Task 2/3a).

INPUT
    measurement/taskb_selected_repos.json            (danh sach 698 repo)
    measurement/experiment/log_validity_audit.json   (category moi repo)
    measurement/taskb_run_data/taskb_step2_urls_v2.json  (R_exec, da fix wrong-job)
    data/policies_ci.jsonl, data/files_ci.jsonl, data/files/*
    measurement/static_rules.json

OUTPUT
    measurement/would_break_result.json

CHAY
    uv run python measurement/compute_would_break.py
"""
from teep import paths as _P
import argparse
import json
from pathlib import Path

from teep.capacity.tighten_policy import compile_rules, static_domains, tighten, host_matches
from teep.capacity.compute_residual_capacity import load_policies

DATA = _P.data("data")


def load_reliable_repos(path):
    """Chi repo category D (block THAT SU duoc enforce, khong fallback audit).
    Xem audit_log_validity.py: A=khong co bang chung HR (nghi sai job),
    B=fallback audit luc runtime, C=khai bao san la audit, E=khong ro."""
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    per_repo = d["per_repo"]
    reliable = {r for r, info in per_repo.items()
                if info.get("category") == "D_declared_block_no_fallback_detected_GOOD"}
    counts = {}
    for info in per_repo.values():
        c = info.get("category", "?")
        counts[c] = counts.get(c, 0) + 1
    return reliable, counts


def load_rexec_workload(path):
    """R_exec(repo) = domain WORKLOAD (TOOLING da loai san boi extract_rlog_v2.py)."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for repo, entries in raw.items():
        hosts = {e["domain"].lower() for e in entries if e.get("classification") == "WORKLOAD"}
        if hosts:
            out[repo] = hosts
    return out


def build_iprime_per_repo(policies, blob_of, rules):
    """Chay lai DUNG tighten() nhu tighten_full_corpus.py tren tung policy,
    hop (union) 'kept' theo repo -> I'(repo). Tra ve (iprime_by_repo,
    n_policy_by_repo, n_no_blob, n_unreadable) de doi chieu sanity voi
    tighten_full_corpus.json neu can.

    CHAN DOAN (them 2026-09-19, sau lan chay dau ra 98.35% - qua cao so
    voi ky vong): tinh SONG SONG 1 bien the I'_broad dung
    static_domains(txt, rules, drop_low=False) - tuc LA MOI rule khop deu
    dong gop domain, KHONG chi ap dung rule 'any_action' (confidence=low)
    khi khong con rule nao khac khop. Ly do nghi ngo: any_action khai bao
    dung 3/6 domain xuat hien lap lai trong vi du dau tien (api.github.com,
    raw.githubusercontent.com, release-assets.githubusercontent.com) nhung
    gan nhu MOI file co 'uses: actions/checkout' (khop rule 'checkout') nen
    dieu kien fallback 'khong con rule nao khac khop' gan nhu KHONG BAO GIO
    dung - any_action bi de-prioritized triet de trong tighten(), du
    static_rules.json 've mat ly thuyet' co biet domain do. Neu would-break
    rate giam manh voi I'_broad -> phan lon 98.35% la do thiet ke
    drop_low=True cua static_domains(), KHONG phai recall gap that cua S1."""
    iprime = {}
    iprime_broad = {}
    n_policy_by_repo = {}
    n_no_blob = n_unreadable = 0
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
        s1, _prov, _matched = static_domains(txt, rules)
        s1_broad, _prov_b, _matched_b = static_domains(txt, rules, drop_low=False)
        kept, _dropped, _reason = tighten(p["hosts"], s1, s3_hosts=None)
        kept_broad, _dropped_b, _reason_b = tighten(p["hosts"], s1_broad, s3_hosts=None)
        iprime.setdefault(p["repo"], set()).update(h.lower() for h in kept)
        iprime_broad.setdefault(p["repo"], set()).update(h.lower() for h in kept_broad)
        n_policy_by_repo[p["repo"]] = n_policy_by_repo.get(p["repo"], 0) + 1
    return iprime, iprime_broad, n_policy_by_repo, n_no_blob, n_unreadable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected-repos", default=str(_P.data("measurement/taskb_selected_repos.json")))
    ap.add_argument("--validity", default=str(_P.data("measurement/experiment/log_validity_audit.json")))
    ap.add_argument("--rexec", default=str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json")))
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--files-index", default=str(_P.data("data/files_ci.jsonl")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--out", default=str(_P.data("measurement/would_break_result.json")))
    ap.add_argument("--show-examples", type=int, default=3,
                     help="in chi tiet N repo co broke != rong de kiem tay")
    a = ap.parse_args()

    selected = json.loads(Path(a.selected_repos).read_text(encoding="utf-8"))["selected"]
    selected_repos = {c["repo"] for c in selected}

    reliable_repos, validity_counts = load_reliable_repos(a.validity)
    print(f"[*] Validity (Task 0), toan bo repo co log: {validity_counts}")
    reliable_in_698 = reliable_repos & selected_repos
    print(f"[*] Repo category D (GOOD) VA nam trong 698 da chon: {len(reliable_in_698)}")

    rexec = load_rexec_workload(a.rexec)
    print(f"[*] Repo co R_exec (WORKLOAD) khac rong, toan bo file: {len(rexec)}")

    rules = compile_rules(a.rules)
    blob_of = {}
    with open(a.files_index, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            blob_of[(d["repo"], d["path"])] = d["blob"]
    policies = load_policies(a.policies)
    print(f"[*] {len(policies)} policy co cuong che, khong template hoa, co host")

    iprime_by_repo, iprime_broad_by_repo, n_policy_by_repo, n_no_blob, n_unreadable = \
        build_iprime_per_repo(policies, blob_of, rules)
    if n_no_blob or n_unreadable:
        print(f"[!] bo qua {n_no_blob} policy khong tim thay blob, "
              f"{n_unreadable} blob khong doc duoc (encoding/IO) khi tinh I'")

    # --- quan the: giao ca 3 dieu kien ---
    eligible = sorted(reliable_in_698 & set(iprime_by_repo) & set(rexec))
    n_skipped_no_iprime = len(reliable_in_698 - set(iprime_by_repo))
    n_skipped_no_rexec = len(reliable_in_698 - set(rexec))
    print(f"\n[*] Quan the xet duoc (category D, co I', co R_exec): {len(eligible)}")
    print(f"    (bo qua {n_skipped_no_iprime} repo category-D khong tinh duoc I' - "
          f"khong co policy nao khop dieu kien load_policies/blob doc duoc)")
    print(f"    (bo qua {n_skipped_no_rexec} repo category-D khong co R_exec WORKLOAD nao)")

    def compute_broke(Iprime, R):
        return {d for d in R if not any(host_matches(pred, d) for pred in Iprime)}

    rows = []
    n_break = n_break_broad = 0
    for repo in eligible:
        R = rexec[repo]
        Iprime = iprime_by_repo[repo]
        Iprime_broad = iprime_broad_by_repo.get(repo, Iprime)
        broke = compute_broke(Iprime, R)
        broke_broad = compute_broke(Iprime_broad, R)
        if broke:
            n_break += 1
        if broke_broad:
            n_break_broad += 1
        rows.append({
            "repo": repo,
            "n_policy": n_policy_by_repo.get(repo, 0),
            "n_iprime": len(Iprime),
            "n_iprime_broad": len(Iprime_broad),
            "n_rexec_workload": len(R),
            "broke": sorted(broke),
            "broke_broad_drop_low_false": sorted(broke_broad),
            "would_break": bool(broke),
            "would_break_broad": bool(broke_broad),
            "explained_by_drop_low_suppression": bool(broke) and not bool(broke_broad),
        })

    n = len(eligible)
    rate = round(100 * n_break / n, 2) if n else None
    rate_broad = round(100 * n_break_broad / n, 2) if n else None
    n_explained = sum(1 for r in rows if r["explained_by_drop_low_suppression"])
    print(f"\n{'='*78}\nWOULD-BREAK RATE\n{'='*78}")
    print(f"  [chinh, giong tighten_full_corpus.json] {n_break}/{n} repo "
          f"({rate}%)" if n else "  (khong co repo nao xet duoc)")
    print(f"  [chan doan, drop_low=False - any_action KHONG bi de-priority] "
          f"{n_break_broad}/{n} repo ({rate_broad}%)")
    print(f"  -> {n_explained}/{n} repo ({round(100*n_explained/n,2) if n else 0}%) "
          f"CHI vi drop_low suppression (het broke khi bo drop_low) - phan con lai "
          f"({n_break_broad}/{n}) la recall gap THAT (domain khong co rule nao ca, "
          f"vd customer-transient-data-*.s3, golangci-lint.run).")

    examples = [r for r in rows if r["would_break"]][:a.show_examples]
    if examples:
        print(f"\n  --- {len(examples)} vi du de kiem tay ---")
        for r in examples:
            print(f"    {r['repo']}  (|I'|={r['n_iprime']}, |I'_broad|={r['n_iprime_broad']}, "
                  f"|R_exec|={r['n_rexec_workload']})")
            print(f"      broke (chinh)      : {r['broke']}")
            print(f"      broke (drop_low=F) : {r['broke_broad_drop_low_false']}")

    Path(a.out).write_text(json.dumps({
        "n_eligible": n,
        "n_would_break": n_break,
        "would_break_rate_pct": rate,
        "n_would_break_broad_drop_low_false": n_break_broad,
        "would_break_rate_broad_pct": rate_broad,
        "n_explained_by_drop_low_suppression": n_explained,
        "n_skipped_no_iprime": n_skipped_no_iprime,
        "n_skipped_no_rexec": n_skipped_no_rexec,
        "validity_counts": validity_counts,
        "rows": rows,
    }, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {a.out}")
    print(f"\n[!] NHAC: n_kept ('chinh') moi policy o day PHAI khop tighten_full_corpus.json")
    print(f"    (cung ham tighten() voi drop_low mac dinh, cung input) - neu Bao doi chieu "
          f"thay lech, bao lai, co the la bug trong script nay.")


if __name__ == "__main__":
    main()
