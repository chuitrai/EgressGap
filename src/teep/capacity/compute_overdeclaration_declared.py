#!/usr/bin/env python3
"""
compute_overdeclaration_declared.py - Task 2, tinh lai voi DUNG dinh nghia
I = allowlist KHAI BAO THAT (declared), khong phai du doan cua S1.

TAI SAO CAN SCRIPT NAY (phat hien 2026-09-12, xem parametric_extraction_notes.md
va cau tra loi ve de xuat Task 3): 2 script Task 2 da co san
(compute_over_declaration.py VA compute_overdeclaration.py - 2 ten gan giong
het nhau) DEU dung "I = D_STATIC[repo]['A']" (S1-A - allowlist S1 TU DU DOAN),
KHONG phai allowlist THAT developer da khai bao. Dinh nghia do MAU THUAN voi
quy uoc I=declared da dung trong evaluate_policy.py/policy_scorecard.py va
DUNG voi de cuong T1 goc ("I = allowlist khai bao"). Con so "55,56%
median-of-ratios" da bao cao truoc day dùng dinh nghia SAI nay - do thuc chat
gan voi "1 - Precision cua S1" hon la "developer khai bao thua bao nhieu".

DINH NGHIA DUNG (script nay):
    I_i = declared_hosts CUA REPO i (tu taskb_selected_repos.json, da loc
          qua is_domain_like() - LOAI IP/SRV/token rac, dung LAI ham da
          sua trong build_learnable_bucket.py, KHONG viet lai logic loc)
    R_i = R_exec WORKLOAD cua repo i (tu taskb_step2_urls_v2.json)
    over_i = |I_i \\ R_i| / |I_i|   (chi tinh repo co R_i khac rong VA |I_i|>0,
             giong dieu kien "quan the chinh" cua 2 script cu, De SO SANH
             DUOC true tiep 3 con so tren CUNG 1 tap repo)
    -> BAO CAO median-of-ratios (CHINH, giong quy uoc da thong nhat) +
       ratio-of-medians (PHU, doi chieu) + P25/P75.

CANH BAO BAT BUOC PHAI DOC TRUOC KHI DUNG SO NAY:
    1. GRANULARITY: R_exec la REPO-level (gop tat ca job/workflow cua 1 repo
       lam 1 tap), con Task 3a/3b (compute_residual_capacity.py,
       tighten_full_corpus.py) la POLICY-level (moi job rieng). Script nay
       KHONG cung don vi phan tich voi Task 3 - KHONG duoc gop chung 1 bang/
       1 claim "per-policy" trong paper voi con so tu day.
    2. DINH CHINH (2026-09-13): dong nay TRUOC DAY ghi "R_exec dang PROVISIONAL,
       ban sua 45,9% wrong-job CHUA chay" - SAI, dua tren 1 memory note CU.
       Doc lai parametric_extraction_notes.md muc 8-9 xac nhan: bug wrong-job
       DA duoc phat hien, sua (Task 0/5), VA CHAY LAI tren corpus mo rong,
       KET QUA ON DINH: rui ro con lai (nhom A+B+C) giam tu 45,9% (255/556)
       xuong 15,5% (86/556) sau fix, roi ~14,0% (92/657) sau khi mo rong
       corpus - "khong xau di khi corpus lon hon, xac nhan co che fix tong
       quat hoa tot" (plan_b_deep_research_prompt.md, Phan 4). File
       taskb_step2_urls_v2.json dung o day LA ban DA QUA FIX (hau to "_v2"
       chinh la ban sua). Vay R_exec KHONG con la "provisional" theo nghia
       "chua fix" - van con ~14% repo co rui ro validity con lai (18/86 repo
       nhom nay chua fetch lai duoc do thieu lenh `gh` CLI, xem muc 9.5),
       CAN ghi vao Limitations cua paper nhu 1 muc ~14% nhieu con lai da biet
       va da do duoc, KHONG phai 1 ly do de coi con so nay la "so bo".
    3. Vi (1), day la 1 con so BO SUNG cho tighten_full_corpus.py's
       "over_decl_S1_median_pct" (S1-based, policy-level, KHONG can R_exec) -
       KHONG PHAI thay the, vi khac granularity (repo vs policy) va khac dinh
       nghia "over" (so voi R_exec THAT vs so voi S1 du doan). Neu 2 con so
       lech nhau, nguyen nhan co the la (a) ~14% nhieu con lai trong R_exec,
       VA/HOAC (b) S1 chua day du (con recall gap da biet) - can bai bao neu
       ro CA HAI nguyen nhan, khong chon 1 con roi bo qua con kia.

CHAY
    uv run python measurement/experiment/compute_overdeclaration_declared.py
"""
from teep import paths as _P
import json
import statistics
import sys
from pathlib import Path

pass  # sys.path hack removed: package imports via teep.*
from teep.static.build_learnable_bucket import is_domain_like  # noqa: E402

SELECTED = json.loads(Path(str(_P.data("measurement/taskb_selected_repos.json"))).read_text(encoding="utf-8"))["selected"]
RLOG_V2 = json.loads(Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json"))).read_text(encoding="utf-8"))

DECLARED_BY_REPO = {}
for c in SELECTED:
    hosts = {h.lower() for h in (c.get("declared_hosts") or []) if is_domain_like(h.lower())}
    DECLARED_BY_REPO[c["repo"]] = hosts

R_EXEC_BY_REPO = {}
for repo, entries in RLOG_V2.items():
    R_EXEC_BY_REPO[repo] = {e["domain"].lower() for e in entries if e["classification"] == "WORKLOAD"}


def percentile(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    f, c = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def analyze(min_I=0):
    per_repo_ratio, I_sizes, inter_sizes = [], [], []
    n_skipped_no_rexec, n_skipped_empty_I = 0, 0
    for repo, I in DECLARED_BY_REPO.items():
        R = R_EXEC_BY_REPO.get(repo)
        if not R:
            n_skipped_no_rexec += 1
            continue
        if len(I) == 0 or len(I) < min_I:
            n_skipped_empty_I += 1
            continue
        over = len(I - R) / len(I)
        per_repo_ratio.append(over)
        I_sizes.append(len(I))
        inter_sizes.append(len(I & R))

    per_repo_ratio.sort()
    I_sizes.sort()
    n = len(per_repo_ratio)
    print(f"\n{'='*78}\nOVER-DECLARATION (I=DECLARED THAT, khong phai S1) - min_I={min_I}, "
          f"n={n} repo\n(bo qua {n_skipped_no_rexec} repo khong co R_exec, "
          f"{n_skipped_empty_I} repo |I|<{max(min_I,1)} sau khi loc is_domain_like)\n{'='*78}")
    if n == 0:
        print("  (khong co repo nao du dieu kien)")
        return None

    med_ratio = statistics.median(per_repo_ratio)
    p25 = percentile(per_repo_ratio, 0.25)
    p75 = percentile(per_repo_ratio, 0.75)
    mean_ratio = statistics.mean(per_repo_ratio)
    med_I = statistics.median(I_sizes)
    med_inter = statistics.median(inter_sizes)
    ratio_of_medians = (med_I - med_inter) / med_I if med_I else float("nan")

    print(f"  [CHINH] median-of-ratios: median={med_ratio*100:.1f}%  "
          f"P25={p25*100:.1f}%  P75={p75*100:.1f}%  mean={mean_ratio*100:.1f}%")
    print(f"  [PHU] ratio-of-medians  : {ratio_of_medians*100:.1f}%   "
          f"(lech so voi CHINH: {abs(med_ratio-ratio_of_medians)*100:.1f} diem %)")

    return {
        "n_repo": n, "n_skipped_no_rexec": n_skipped_no_rexec,
        "n_skipped_min_I": n_skipped_empty_I,
        "median_of_ratios_pct": round(med_ratio * 100, 2),
        "p25_pct": round(p25 * 100, 2), "p75_pct": round(p75 * 100, 2),
        "mean_of_ratios_pct": round(mean_ratio * 100, 2),
        "median_I": med_I, "median_intersection": med_inter,
        "ratio_of_medians_pct": round(ratio_of_medians * 100, 2),
    }


results = {}
print("I = declared_hosts THAT (taskb_selected_repos.json, loc is_domain_like)")
print("R = R_exec WORKLOAD (taskb_step2_urls_v2.json) - ban DA fix wrong-job "
      "(Task 0/5), ~14% nhieu con lai da biet, xem docstring")
results["declared_min_I_0"] = analyze(min_I=0)
results["declared_min_I_5"] = analyze(min_I=5)

Path(str(_P.data("measurement/over_declaration_declared.json"))).write_text(
    json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
print("\n>>> measurement/over_declaration_declared.json")
print("\n[!] NHAC LAI: R_exec o day DA fix wrong-job (Task 0/5, ~14% nhieu con lai "
      "da biet, KHONG con la 45,9%) nhung KHAC granularity voi Task 3 "
      "(repo-level, khong phai policy-level) - dung gop chung 1 bang.")
