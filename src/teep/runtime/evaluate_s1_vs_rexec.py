#!/usr/bin/env python3
"""
evaluate_s1_vs_rexec.py - Do Precision/Recall/F1 (nhom metric chinh) + Resolution
Rate + Workflow Coverage + Error/Failure breakdown cho S1-A (static_rules.json)
va S1-B (+ parametric/Cosseter), doi chieu voi R_exec (Task B, R_log v2,
WORKLOAD-only). S1-C (+ data-flow) da co san trong d_static_versions.json nhung
CHUA duoc yeu cau do hom nay - in them o cuoi de tham khao, khong phai trong tam.

QUAN TRONG - pham vi so sanh: CHI tinh tren cac repo CO BANG CHUNG (>=1 domain
WORKLOAD trong R_exec). Ly do: R_exec la "execution-derived reference", KHONG
phai ground truth tuyet doi (R_exec ⊆ R_true - 1 lan crawl khong chac kich hoat
het moi nhanh mang hop le). Neu tinh ca repo R_exec=∅, moi domain S1 du doan se
bi tinh False Positive GIA TAO (khong co bang chung, khong co nghia la SAI) -
lam sai lech Precision mot cach he thong. Van bao cao ca quan the day du (n=555,
bao gom repo R_exec rong) o phan sensitivity de khong giau thong tin.

CACH DOC KET QUA (giu dung khung dien giai da thong nhat):
    "S1 dat Precision X% SO VOI execution-derived reference"
    KHONG duoc noi: "X% du doan cua S1 la sai" (vi FP co the la domain that nhung
    R_exec chua quan sat thay o lan crawl nay).

CAP NHAT 2026-09-10 (Task 1, sau deep-research Q1 - PU-learning framing):
    R_exec la 1 tap POSITIVE-UNLABELED (PU): domain S1 du doan nhung KHONG co
    trong R_exec co the la dung-nhung-chua-quan-sat-duoc, khong chac la sai
    (Bekker & Davis 2020; tien le sat nhat: Samhi et al. ISSTA 2024 lam dung y
    het - so call graph tinh voi runtime, bo han Precision). Theo ly thuyet
    PU-learning, Recall UOC LUONG DUOC tu du lieu PU nhung Precision THI KHONG
    - VOI DIEU KIEN giả dinh SCAR (Selected Completely At Random: viec 1 domain
    "lot vao" R_exec hay khong phai NGAU NHIEN, khong phu thuoc dac diem domain
    do) dung. Giả dinh SCAR GAN NHU CHAC CHAN SAI o day, vi 1 domain co xuat
    hien trong R_exec hay khong phu thuoc CHINH vao loai tool phat ra request
    (tool nao co DNS query Harden-Runner ghi lai duoc) - day la SAR/SNAR
    (Selected At/Not At Random), khong phai SCAR.
    HE QUA CU THE cho cach doc/bao cao con so:
      - Recall (ca micro/macro) PHAI duoc goi la "CAN DUOI" (lower bound) cua
        Recall that tren R_true, KHONG duoc noi la uoc luong khong thien lech.
      - Precision/F1 KHONG duoc dung lam so dau bang trong paper - chi in o
        day de tham khao/debug, KHONG trich nhu 1 ket qua khong thien lech.
      - FN (= |R_exec \\ D|) chinh la "coverage gap" - day moi la so quan
        trong nhat ve mat van hanh (domain thuc su can nhung S1 bo sot se lam
        vo build duoi egress-policy: block) - uu tien doc/bao cao so nay hon
        Precision.
    Neu can 1 so kieu Precision cho paper, dung thiet ke manual-sample-
    verification (lay mau ngau nhien domain S1 du doan nhung khong co trong
    R_exec, doc tay phan loai dung/sai, bao cao ty le uoc luong kem CI) - CHUA
    lam, chi lam neu reviewer thuc su doi.

CHAY
    uv run python measurement/evaluate_s1_vs_rexec.py
"""
from teep import paths as _P
import json
import statistics
from pathlib import Path
from collections import Counter

D_STATIC = json.loads(Path(str(_P.data("measurement/d_static_versions.json"))).read_text(encoding="utf-8"))
RLOG_V2 = json.loads(Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json"))).read_text(encoding="utf-8"))
STATIC_RULES = json.loads(Path(str(_P.config("static_rules.json"))).read_text(encoding="utf-8"))["rules"]
PARAMETRIC = json.loads(Path(str(_P.data("measurement/parametric_targets.json"))).read_text(encoding="utf-8"))
SELECTED_REPOS = set(D_STATIC.keys())

# tap domain "S1 biet ten" (tu dien domain cua static_rules.json, KHONG tinh
# rule ecosystem='tooling' vi da tach rieng khoi D_static tu dau) - dung cho
# Error/Failure bucket 1 vs 2 (muc 4 ben duoi).
KNOWN_DOMAIN_VOCAB = set()
for r in STATIC_RULES:
    if r.get("ecosystem") == "tooling":
        continue
    for d in r["domains"]:
        if not d.startswith("*."):
            KNOWN_DOMAIN_VOCAB.add(d.lower())

R_exec_by_repo = {}
for repo, entries in RLOG_V2.items():
    R_exec_by_repo[repo] = {e["domain"] for e in entries if e["classification"] == "WORKLOAD"}

rows_full = []   # n=555 (moi repo co du lieu R_log v2, ke ca R_exec rong)
rows_evd = []    # n=373 (chi repo co >=1 domain WORKLOAD - quan the CHINH)
for repo in SELECTED_REPOS:
    if repo not in R_exec_by_repo:
        continue  # khong co du lieu Task B cho repo nay (vd 404/no_run/parse_error)
    R = R_exec_by_repo[repo]
    d = D_STATIC[repo]
    row = {"repo": repo, "R_exec": R, "A": set(d["A"]), "B": set(d["B"]), "C": set(d["C"])}
    rows_full.append(row)
    if R:
        rows_evd.append(row)

print(f"[*] Corpus D_static: {len(SELECTED_REPOS)} repo")
print(f"[*] Co du lieu R_log v2 (n=555 ky vong): {len(rows_full)} repo")
print(f"[*] Co >=1 domain WORKLOAD (quan the CHINH, n=373 ky vong): {len(rows_evd)} repo")


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else float("nan")
    r = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * p * r / (p + r) if (p + r) and p == p and r == r and (p + r) > 0 else float("nan")
    return p, r, f1


def evaluate(rows, version_key, label):
    tp_total = fp_total = fn_total = 0
    macro_p, macro_r, macro_f1 = [], [], []
    n_fully_covered = 0
    fn_domains_agg = Counter()
    for row in rows:
        R, D = row["R_exec"], row[version_key]
        tp = len(D & R)
        fp = len(D - R)
        fn = len(R - D)
        tp_total += tp; fp_total += fp; fn_total += fn
        if fn == 0:
            n_fully_covered += 1
        for dom in (R - D):
            fn_domains_agg[dom] += 1
        p, r, f1 = prf(tp, fp, fn)
        if p == p:  # khong phai NaN (repo co >=1 domain trong D)
            macro_p.append(p)
        if r == r:
            macro_r.append(r)
        if f1 == f1:
            macro_f1.append(f1)

    micro_p, micro_r, micro_f1 = prf(tp_total, fp_total, fn_total)
    print(f"\n=== {label} (n={len(rows)} repo) ===")
    print(f"  TP={tp_total}  FP={fp_total}  FN={fn_total}")
    print(f"  MICRO   Precision={micro_p:.3f}  Recall={micro_r:.3f}  F1={micro_f1:.3f}")
    print(f"  MACRO   Precision={statistics.mean(macro_p):.3f}  Recall={statistics.mean(macro_r):.3f}  "
          f"F1={statistics.mean(macro_f1):.3f}  (trung binh cong tung repo, trong so bang nhau)")
    print(f"  Workflow/repo coverage (FN=0, moi domain quan sat duoc deu duoc du doan): "
          f"{n_fully_covered}/{len(rows)} = {100*n_fully_covered/len(rows):.1f}%")
    # 2026-09-10, theo verdict Q1 cua deep-research validate Plan B: R_exec la
    # PU (positive-unlabeled) reference, va gia dinh SCAR (viec 1 domain co
    # "lot vao" R_exec hay khong doc lap voi dac diem domain) GAN NHU CHAC
    # CHAN SAI o day - domain co xuat hien trong R_exec hay khong phu thuoc
    # CHINH vao loai tool phat ra request (tool nao co DNS query Harden-Runner
    # ghi duoc). He qua: Recall KHONG con la uoc luong khong thien lech cua
    # Recall that (tren R_true) nua, ma CHI la CAN DUOI - vi 1 lan crawl
    # khong bat het moi nhanh hop le. Precision van KHONG duoc bao cao nhu so
    # khong thien lech (chuan PU-learning: Elkan & Noto 2008, Bekker & Davis
    # 2020 survey) - domain S1 du doan nhung R_exec khong co CO THE la dung-
    # nhung-chua-quan-sat-duoc, khong chac la sai. Tien le sat nhat lam dung
    # y het (Samhi et al., ISSTA 2024): bo han Precision, chi bao cao Recall/
    # soundness 1 chieu so voi runtime trace.
    print("  [DOC NHU THE NAO] Recall o tren la CAN DUOI (lower bound) cua Recall that, KHONG PHAI")
    print("  uoc luong khong thien lech - vi gia dinh SCAR (PU-learning) khong dung o day (xem Q1,")
    print("  plan_b_deep_research_prompt.md). Precision KHONG duoc bao cao nhu 'X% du doan sai' -")
    print("  domain FP co the la dependency that nhung R_exec chua quan sat thay o lan crawl nay.")
    return {
        "n_repo": len(rows), "tp": tp_total, "fp": fp_total, "fn": fn_total,
        "micro_precision": round(micro_p, 4), "micro_recall": round(micro_r, 4), "micro_f1": round(micro_f1, 4),
        "macro_precision": round(statistics.mean(macro_p), 4),
        "macro_recall": round(statistics.mean(macro_r), 4),
        "macro_f1": round(statistics.mean(macro_f1), 4),
        "n_repo_fully_covered": n_fully_covered,
        "pct_repo_fully_covered": round(100 * n_fully_covered / len(rows), 2),
        "top_fn_domains": fn_domains_agg.most_common(15),
        "metric_status": {
            "recall": "lower_bound_not_unbiased_SCAR_violated",
            "precision": "not_estimable_PU_reference_do_not_report_as_unbiased",
            "reference": "Q1 verdict, plan_b_deep_research_prompt.md; Bekker & Davis 2020; Samhi et al. ISSTA 2024",
        },
    }


results = {}
print("\n" + "=" * 78)
print("NHOM METRIC 1: PRECISION / RECALL / F1 (chinh)")
print("=" * 78)
for key, label in [("A", "S1-A (static_rules.json)"), ("B", "S1-B (+ parametric/AST Semgrep)")]:
    results[f"evd_{key}"] = evaluate(rows_evd, key, f"{label} - QUAN THE CHINH (repo co bang chung)")
    results[f"full_{key}"] = evaluate(rows_full, key, f"{label} - sensitivity (ca repo R_exec rong)")

# --- NHOM METRIC 2: Resolution Rate (tang PARAMETRIC, pham vi dung 609 repo) ---
print("\n" + "=" * 78)
print("NHOM METRIC 2: RESOLUTION RATE (tang parametric/Cosseter, pham vi 609 repo Task B)")
print("=" * 78)
print("  S1-A (static_rules.json): KHONG co khai niem resolved/unresolved - moi regex")
print("  khop la ra domain ngay, khong co 'network sink chua resolve duoc'. Resolution")
print("  Rate CHI ap dung tu tang parametric (S1-B) tro di.")

rows_609 = [r for r in PARAMETRIC["rows"] if r["repo"] in SELECTED_REPOS]
res_counter = Counter(r["resolution"] for r in rows_609)
total_609 = len(rows_609)
resolution_rate = res_counter.get("RESOLVED", 0) / total_609 if total_609 else float("nan")
print(f"  So dong PARAMETRIC (curl/wget/git-clone/helm) trong 609 repo: {total_609}")
for k, v in res_counter.most_common():
    print(f"    {k:<20}{v:>5}  ({100*v/total_609:.1f}%)")
print(f"  Resolution Rate (S1-B) = RESOLVED / tong = {resolution_rate*100:.1f}%")
print(f"  Unresolved Rate = {100*(1-resolution_rate):.1f}%")
results["resolution_rate_s1b"] = {
    "n_lines": total_609, "breakdown": dict(res_counter),
    "resolution_rate_pct": round(resolution_rate * 100, 2) if resolution_rate == resolution_rate else None,
}

# --- NHOM METRIC 4: Error / Failure analysis cho FN cua S1-A va S1-B (quan the chinh) ---
print("\n" + "=" * 78)
print("NHOM METRIC 4: ERROR / FAILURE ANALYSIS (FN domains, quan the chinh n=373)")
print("=" * 78)
print("  2 bucket kiem duoc RE MA KHONG DOAN THEM (can doc tay moi phan loai sau hon):")
print("  (a) domain NAM TRONG tu dien domain cua static_rules.json (S1 'biet ten' domain")
print("      nay o repo khac) nhung KHONG duoc du doan o repo nay -> rule co san khong")
print("      khop dung TEXT cua repo nay (co the do bien the cu phap, hoac domain trung")
print("      ten ngau nhien giua cac ecosystem).")
print("  (b) domain KHONG nam trong bat ky danh sach domain nao cua static_rules.json ->")
print("      KHONG co rule nao cho ecosystem/domain nay - khoang trong coverage that su.")

for key, label in [("A", "S1-A"), ("B", "S1-B")]:
    bucket_known, bucket_unknown = 0, 0
    unknown_examples = Counter()
    for row in rows_evd:
        fn = row["R_exec"] - row[key]
        for dom in fn:
            if dom in KNOWN_DOMAIN_VOCAB:
                bucket_known += 1
            else:
                bucket_unknown += 1
                unknown_examples[dom] += 1
    total_fn = bucket_known + bucket_unknown
    print(f"\n  {label}: tong {total_fn} luot FN (domain-repo)")
    if total_fn:
        print(f"    (a) da co trong tu dien S1 nhung khong khop o repo nay: {bucket_known} "
              f"({100*bucket_known/total_fn:.1f}%)")
        print(f"    (b) khong co rule nao cho domain/ecosystem nay:         {bucket_unknown} "
              f"({100*bucket_unknown/total_fn:.1f}%)")
    print("    Top domain kieu (b) (khong co rule nao) - uu tien them rule moi:")
    for dom, n in unknown_examples.most_common(10):
        print(f"      {dom:<40}{n}")

# --- S1-C, chi in tham khao (KHONG phai trong tam yeu cau hom nay) ---
print("\n" + "=" * 78)
print("(THAM KHAO, chua duoc yeu cau) S1-C (+ lightweight data-flow) - quan the chinh")
print("=" * 78)
results["evd_C_preview"] = evaluate(rows_evd, "C", "S1-C preview")

Path(str(_P.data("measurement/s1_vs_rexec_evaluation.json"))).write_text(
    json.dumps(results, indent=2, ensure_ascii=False, default=list), encoding="utf-8"
)
print("\n>>> measurement/s1_vs_rexec_evaluation.json")
