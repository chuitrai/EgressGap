"""
rlog_v2_stats.py - Thong ke median/mean/P25/P75 tren R_exec (WORKLOAD-only, sau khi da
loai TOOLING va noise) doi chieu voi I (allowlist da khai bao), theo dung 5 chi so Bao yeu
cau: |R_exec|, |I|, |R_exec giao I|, |R_exec - I|, ty le |I|/|R_exec|. Tinh tren 2 quan
the: toan bo repo co du lieu (bao gom ca R_exec=0) va chi repo co >=1 domain WORKLOAD.
"""
from teep import paths as _P
import json
import statistics
from pathlib import Path


def host_matches(domain, declared_hosts):
    d = domain.lower()
    for h in declared_hosts:
        h = h.lower()
        if h == d:
            return True
        if h.startswith("*.") and d.endswith(h[1:]):
            return True
    return False


selected = json.loads(Path(str(_P.data("measurement/taskb_selected_repos.json"))).read_text(encoding="utf-8"))["selected"]
repo_to_I = {c["repo"]: [h.lower() for h in c["declared_hosts"]] for c in selected}
safe_to_real = {c["repo"].replace("/", "_"): c["repo"] for c in selected}

rlog_v2 = json.loads(Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json"))).read_text(encoding="utf-8"))

rows = []
for repo, entries in rlog_v2.items():
    if repo not in repo_to_I:
        continue
    I = repo_to_I[repo]
    R_exec = sorted({e["domain"] for e in entries if e["classification"] == "WORKLOAD"})
    R_tooling = sorted({e["domain"] for e in entries if e["classification"] == "TOOLING"})
    inter = [d for d in R_exec if host_matches(d, I)]
    only_log = [d for d in R_exec if not host_matches(d, I)]
    rows.append({
        "repo": repo, "n_I": len(I), "n_R_exec": len(R_exec), "n_R_tooling": len(R_tooling),
        "n_inter": len(inter), "n_only_log": len(only_log),
    })

n_total_selected = len(selected)
n_with_R_exec = sum(1 for r in rows if r["n_R_exec"] > 0)
print(f"tong so repo selected: {n_total_selected}")
print(f"so repo co du lieu R_log v2 (>=0 entry, co extracted/): {len(rows)}")
print(f"so repo co >=1 domain WORKLOAD (R_exec khong rong): {n_with_R_exec}")

# Theo dung yeu cau: tinh tren cac repo CO R_exec (khac rong) - vi median cua tap
# co nhieu so 0 se bi keo lech, va cau hoi dat ra la "trong nhung gi quan sat duoc"
for label, subset in [("TOAN BO repo co du lieu (bao gom 0)", rows),
                       ("CHI repo co >=1 domain WORKLOAD", [r for r in rows if r["n_R_exec"] > 0])]:
    print(f"\n--- {label} (n={len(subset)}) ---")
    if not subset:
        continue
    r_exec_vals = [r["n_R_exec"] for r in subset]
    i_vals = [r["n_I"] for r in subset]
    inter_vals = [r["n_inter"] for r in subset]
    only_log_vals = [r["n_only_log"] for r in subset]

    def pctl(vals, p):
        vals = sorted(vals)
        k = (len(vals) - 1) * p
        f, c = int(k), min(int(k) + 1, len(vals) - 1)
        return vals[f] + (vals[c] - vals[f]) * (k - f)

    print(f"  median |R_exec| = {statistics.median(r_exec_vals)}   mean = {round(statistics.mean(r_exec_vals),2)}   "
          f"P25 = {round(pctl(r_exec_vals,0.25),1)}   P75 = {round(pctl(r_exec_vals,0.75),1)}")
    print(f"  median |I|      = {statistics.median(i_vals)}   mean = {round(statistics.mean(i_vals),2)}")
    print(f"  median |R_exec (cap) I| = {statistics.median(inter_vals)}   mean = {round(statistics.mean(inter_vals),2)}")
    print(f"  median |R_exec - I| (chi trong log) = {statistics.median(only_log_vals)}   mean = {round(statistics.mean(only_log_vals),2)}")
    ratios = [r["n_I"] / r["n_R_exec"] for r in subset if r["n_R_exec"] > 0]
    if ratios:
        print(f"  median (|I| / |R_exec|) tinh tung repo = {round(statistics.median(ratios),2)}")

    # --- SUA THEO Q3 (deep-research xac nhan, 2026-09-10): so "over-declaration
    # ~69%" truoc day tinh bang ratio-of-medians - (median|I| - median(I cap
    # R_exec)) / median|I| - KHONG dung quy uoc cua tai lieu do-luong
    # over-permission (Felt et al., CCS 2011, bao cao PHAN PHOI per-app, khong
    # phai ty le 2 median), va VE MAT SO HOC KHAC voi median-of-ratios (vi du
    # thuc te lech toi 21% trong 1 nghien cuu thien van duoc deep-research dan
    # ra). SO CHINH THUC tu gio la per-repo median-of-ratios:
    #     over_declaration(repo) = |I \ R_exec| / |I| = (n_I - n_inter) / n_I
    # chi tinh tren repo co |I|>0, roi lay median/IQR cua CHINH ty le do (khong
    # phai ty le cua 2 median rieng biet). Giu lai so ratio-of-medians ben duoi
    # lam so PHU, ghi chu ro - KHONG dung lam so dau bang trong paper nua.
    over_decl_ratios = [(r["n_I"] - r["n_inter"]) / r["n_I"] for r in subset if r["n_I"] > 0]
    n_excluded_zero_I = sum(1 for r in subset if r["n_I"] == 0)
    if over_decl_ratios:
        med = statistics.median(over_decl_ratios)
        p25, p75 = pctl(over_decl_ratios, 0.25), pctl(over_decl_ratios, 0.75)
        print(f"\n  [Q3-fix] OVER-DECLARATION - SO CHINH (median-of-ratios, per-repo, |I|>0, n={len(over_decl_ratios)}):")
        print(f"    median = {round(med*100,1)}%   IQR = [{round(p25*100,1)}%, {round(p75*100,1)}%]   "
              f"mean = {round(statistics.mean(over_decl_ratios)*100,1)}%")
        if n_excluded_zero_I:
            print(f"    (da loai {n_excluded_zero_I} repo |I|=0 - khong chia duoc)")

        # so PHU (cach tinh CU) - chi de doi chieu, KHONG dung lam headline
        median_I = statistics.median(i_vals)
        median_inter = statistics.median(inter_vals)
        ratio_of_medians = (median_I - median_inter) / median_I if median_I else float("nan")
        print(f"    [so PHU, cach cu - ratio-of-medians] (median|I| - median(I cap R_exec)) / median|I| "
              f"= ({median_I} - {median_inter}) / {median_I} = {round(ratio_of_medians*100,1)}%  "
              f"(chenh {round((ratio_of_medians-med)*100,1)} diem % so voi so chinh o tren - "
              f"KHONG PHAI cung 1 dai luong, xem muc 8 cua note ve ly do)")

        # sensitivity check (Q3, deep-research khuyen nghi): loai repo |I| rat
        # nho xem median-of-ratios co doi nhieu khong (repo |I| nho de bi 1
        # domain le keo ty le len/xuong cuc doan, vd |I|=1 va thieu 1 domain ->
        # 100% over-declaration ngay lap tuc).
        for min_I in (3, 5):
            sub_ratios = [(r["n_I"] - r["n_inter"]) / r["n_I"] for r in subset if r["n_I"] >= min_I]
            if sub_ratios:
                print(f"    sensitivity (chi repo |I|>={min_I}, n={len(sub_ratios)}): "
                      f"median = {round(statistics.median(sub_ratios)*100,1)}%")

Path(str(_P.data("measurement/taskb_run_data/rlog_v2_per_repo_stats.json"))).write_text(
    json.dumps(rows, indent=1, ensure_ascii=False), encoding="utf-8"
)
