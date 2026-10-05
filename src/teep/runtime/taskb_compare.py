#!/usr/bin/env python3
"""
taskb_compare.py - Task B, Buoc 3+4: doi chieu R_log (tu Buoc 1-2) voi I
(allowlist da khai bao, lay tu data/policies_ci.jsonl - CHINH LA nguon da
dung xuyen suot du an, khong doc lai tu dau) - va TU DONG ap dung bang quyet
dinh Buoc 4, khong de nguoi doc phai tu cong so.

DAU VAO
    measurement/taskb_selected_repos.json   (Buoc 0 - I cua tung repo)
    measurement/taskb_run_data/taskb_step1_results.csv  (Buoc 1 - tai duoc khong)
    measurement/taskb_run_data/taskb_step2_urls.json    (Buoc 2 - R_log tung repo)

Neu 2 file Buoc 1-2 CHUA TON TAI (vi may nay khong goi duoc api.github.com,
xem taskb_actions_log_feasibility_notes.md), script tu chuyen sang CHE DO
DRY-RUN: sinh du lieu R_log GIA LAP (synthetic) chi de kiem tra logic tinh
toan (dung dung 2 dong vi du trong huong dan cua thay: r1 |I|=8 |R|=5
trung=5, r2 |I|=12 |R|=3 trung=3) va IN RO "DAY LA DU LIEU GIA" o dau va cuoi
output - khong duoc nham day la ket qua that.

CACH DOC BANG 5 COT (dung tu huong dan cua thay)
    |I| khai bao       - so host duy nhat trong allowlist da khai bao
    |R_log| trich duoc - so domain phan biet grep duoc tu log that
    trung              - |I ∩ R_log| (dung host_matches, co xu ly wildcard *.)
    chi trong I         - |I \\ R_log| - allowlist co nhung log khong thay goi
                          (co the nhanh do khong chay trong lan crawl nay)
    chi trong log        - |R_log \\ I| - QUAN TRONG NHAT: domain workflow THAT
                          SU goi ma allowlist KHONG khai bao -> hoac allowlist
                          se hong build that (nhanh nay chua chay luc build),
                          hoac chinh no la evidence R that (neu allowlist DANG
                          block ma van chay duoc -> domain nay phai nam trong
                          E, khong phai I - dang dieu tra).

CHAY
    python measurement/taskb_compare.py
"""
from teep import paths as _P
import csv
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SELECTED = Path(str(_P.data("measurement/taskb_selected_repos.json")))
RUN_DIR = Path(str(_P.data("measurement/taskb_run_data")))
RESULTS_CSV = RUN_DIR / "taskb_step1_results.csv"
URLS_JSON = RUN_DIR / "taskb_step2_urls.json"
OUT = Path(str(_P.data("measurement/taskb_comparison_result.json")))


def host_matches(domain, declared_hosts):
    """Y het logic dung trong evaluate_parametric_evidence.py - GIU DONG NHAT
    trong toan bo du an, khong viet lai kieu khac."""
    d = domain.lower()
    for h in declared_hosts:
        h = h.lower()
        if h == d:
            return True
        if h.startswith("*.") and d.endswith(h[1:]):
            return True
    return False


def set_diff_with_wildcard(a_set, b_declared_list):
    """Phan tu cua a_set KHONG khop bat ky host nao trong b_declared_list
    (co wildcard)."""
    return {x for x in a_set if not host_matches(x, b_declared_list)}


def set_inter_with_wildcard(a_set, b_declared_list):
    return {x for x in a_set if host_matches(x, b_declared_list)}


def build_synthetic_dry_run():
    """Dung DUNG 2 vi du so trong huong dan cua thay de tu-kiem-tra script
    tinh dung truoc khi Bao chay du lieu that. KHONG phai ket qua nghien cuu."""
    selected = {
        "selected": [
            {"repo": "SYNTHETIC/r1-vi-du-cua-thay", "declared_hosts":
                ["h1.example", "h2.example", "h3.example", "h4.example",
                 "h5.example", "h6.example", "h7.example", "h8.example"]},
            {"repo": "SYNTHETIC/r2-vi-du-cua-thay", "declared_hosts":
                ["h1.example", "h2.example", "h3.example", "h4.example",
                 "h5.example", "h6.example", "h7.example", "h8.example",
                 "h9.example", "h10.example", "h11.example", "h12.example"]},
        ]
    }
    # r1: |I|=8, |R|=5, trung=5, chi_I=3, chi_log=0 -> R la tap con cua I,
    # 5 host dau cua I duoc "goi that" theo log, 3 host cuoi khong thay.
    # r2: |I|=12, |R|=3, trung=3, chi_I=9, chi_log=0 -> tuong tu, R nho hon nhieu.
    urls = {
        "SYNTHETIC/r1-vi-du-cua-thay": [
            {"domain": "h1.example", "count": 4},
            {"domain": "h2.example", "count": 3},
            {"domain": "h3.example", "count": 2},
            {"domain": "h4.example", "count": 1},
            {"domain": "h5.example", "count": 1},
        ],
        "SYNTHETIC/r2-vi-du-cua-thay": [
            {"domain": "h1.example", "count": 2},
            {"domain": "h2.example", "count": 1},
            {"domain": "h3.example", "count": 1},
        ],
    }
    step1_rows = [
        {"repo": "SYNTHETIC/r1-vi-du-cua-thay", "zip_ok": "True", "n_urls": "5",
         "run_id": "111", "log_http_status": "200", "error_type": "ok"},
        {"repo": "SYNTHETIC/r2-vi-du-cua-thay", "zip_ok": "True", "n_urls": "3",
         "run_id": "222", "log_http_status": "200", "error_type": "ok"},
    ]
    return selected, urls, step1_rows


def main():
    dry_run = not (RESULTS_CSV.exists() and URLS_JSON.exists())

    if dry_run:
        print("=" * 78)
        print("!! CHE DO DRY-RUN - CHUA CO DU LIEU THAT TU BUOC 1-2 !!")
        print(f"   (khong thay {RESULTS_CSV} va/hoac {URLS_JSON})")
        print("   Dung 2 vi du SO trong huong dan cua thay de tu-kiem-tra logic")
        print("   tinh toan. DAY KHONG PHAI KET QUA NGHIEN CUU THAT.")
        print("   Chay measurement/taskb_fetch_and_grep.sh tren may co gh CLI +")
        print("   mang khong bi chan truoc, roi chay lai script nay.")
        print("=" * 78)
        selected_data, urls_data, step1_rows = build_synthetic_dry_run()
    else:
        selected_data = json.loads(SELECTED.read_text(encoding="utf-8"))
        urls_data = json.loads(URLS_JSON.read_text(encoding="utf-8"))
        # QUAN TRONG: module csv coi CA \r don le (khong di kem \n) la 1 line
        # terminator (dung dialect mac dinh), bat ke newline="" hay khong - neu
        # file dau vao co \r lac giua dong (dung bug da tim thay: jq Windows
        # ghi CRLF, $repo dinh \r), csv se tach nham 1 dong thanh 2. Da sua tan
        # goc o taskb_fetch_and_grep.sh, nhung van loai bo het \r tai day nhu
        # 1 lop phong thu, de doc duoc ca file cu (truoc khi sua) ma khong crash.
        # newline="" O DAY LA BAT BUOC, khong phai tuy chon: neu khong, Python
        # tu dich universal-newlines NGAY LUC READ (truoc ca khi code nay chay),
        # bien moi \r don le thanh \n San, roi .replace("\r","") ben duoi se
        # khong con gi de xoa nua (da kiem chung: thieu newline="" van ra 1217
        # dong dung y het loi cu, VI Python da tach \r thanh dong moi tu truoc).
        with RESULTS_CSV.open(encoding="utf-8", newline="") as f:
            raw_text = f.read().replace("\r", "")
        step1_rows = list(csv.DictReader(raw_text.splitlines()))

    step1_by_repo = {r["repo"]: r for r in step1_rows}

    rows_out = []
    print(f"\n{'repo':45s} {'|I|':>4s} {'|R_log|':>8s} {'trung':>6s} "
          f"{'chi_I':>6s} {'chi_log':>8s}")
    print("-" * 90)

    for c in selected_data["selected"]:
        repo = c["repo"]
        I = set(h.lower() for h in c["declared_hosts"])
        r_entries = urls_data.get(repo, [])
        R = set(e["domain"].lower() for e in r_entries)

        inter = set_inter_with_wildcard(R, list(I))
        # chi-trong-I: host cua I KHONG duoc khop boi bat ky domain nao trong R
        # (chieu nguoc lai voi inter, dung host_matches voi vai tro doi cho vi
        # host_matches(domain, declared_list) khong doi xung khi co wildcard)
        only_I = {h for h in I if not any(host_matches(r, [h]) for r in R)}
        only_log = set_diff_with_wildcard(R, list(I))

        row = {
            "repo": repo,
            "n_I": len(I),
            "n_R_log": len(R),
            "n_trung": len(inter),
            "n_chi_trong_I": len(only_I),
            "n_chi_trong_log": len(only_log),
            "domains_chi_trong_log": sorted(only_log),
            "zip_ok": step1_by_repo.get(repo, {}).get("zip_ok", ""),
        }
        rows_out.append(row)
        print(f"{repo:45s} {row['n_I']:>4d} {row['n_R_log']:>8d} {row['n_trung']:>6d} "
              f"{row['n_chi_trong_I']:>6d} {row['n_chi_trong_log']:>8d}")

    # --- Buoc 3.5: TACH RIENG failure mode truoc khi quyet dinh (theo audit
    # 608/609 - KHONG duoc gop "API that bai" chung voi "genuinely khong co
    # completed run" nua, xem taskb_actions_log_feasibility_notes.md muc 7-9) ---
    n_total = len(step1_rows) if not dry_run else len(rows_out)

    def et(r):
        return str(r.get("error_type", ""))

    n_api_failed = sum(1 for r in step1_rows if et(r).startswith("download_error_") or et(r).startswith("api_"))
    n_no_run_genuine = sum(1 for r in step1_rows if et(r) in ("no_run_genuine", "no_completed_run_genuine"))
    n_completed_found = sum(1 for r in step1_rows if r.get("run_id"))
    n_log_downloadable = sum(1 for r in step1_rows if str(r.get("log_http_status")) == "200")
    n_valid_zip = sum(1 for r in step1_rows if str(r.get("zip_ok")).lower() == "true")
    n_with_url = sum(1 for r in rows_out if r["n_R_log"] > 0)
    n_with_3plus = sum(1 for r in rows_out if r["n_R_log"] >= 3)
    n_log_403 = sum(1 for r in step1_rows if et(r) == "log_403_permission")
    n_no_jobs = sum(1 for r in step1_rows if et(r) == "no_jobs_run_never_executed")
    n_no_log_jobs_ran = sum(1 for r in step1_rows if et(r) == "no_log_despite_jobs_ran_SUSPICIOUS")
    n_log_404_ambiguous = sum(1 for r in step1_rows if et(r) == "log_404_unavailable")
    n_log_404_suspicious_unknown_jobs = sum(
        1 for r in step1_rows if et(r) == "log_404_unavailable_run_under_90d_SUSPICIOUS"
    )
    n_redirect = sum(1 for r in step1_rows if "http301" in et(r) or "http302" in et(r))
    n_with_gap = sum(1 for r in rows_out if r["n_chi_trong_log"] > 0)

    # --- Gom ve DUNG 7 nhom Bao yeu cau bao cao (ok/404/no_run/no_jobs/no_log/
    # download_error/parse_error) - KHONG doi ten error_type chi tiet trong CSV
    # (van giu de dieu tra sau), chi anh xa sang nhan ro rang hon o day. Muc
    # dich: phan biet ro "loi he thong/API" (download_error) voi "repo/run hop
    # le nhung khong co job" (no_jobs) voi "job da chay ma van khong co log"
    # (no_log, con mo, can dieu tra tiep) voi "404 chua ro nguyen nhan vi /jobs
    # cung khong goi duoc" (404 generic).
    def bucket_of(r):
        e = et(r)
        if e in ("ok", "ok_but_0_urls_in_grep"):
            return "ok"
        if e in ("no_run_genuine", "no_completed_run_genuine"):
            return "no_run"
        if e == "no_jobs_run_never_executed":
            return "no_jobs"
        if e == "no_log_despite_jobs_ran_SUSPICIOUS":
            return "no_log"
        if e in ("log_404_unavailable", "log_404_unavailable_run_under_90d_SUSPICIOUS"):
            return "404"
        if e == "log_200_but_invalid_zip":
            return "parse_error"
        if e.startswith("download_error_") or e.startswith("api_") or e in (
            "log_403_permission",
        ) or e.startswith("log_http"):
            return "download_error"
        return "unclassified_" + e if e else "unclassified_empty"

    bucket_counts = {}
    for r in step1_rows:
        b = bucket_of(r)
        bucket_counts[b] = bucket_counts.get(b, 0) + 1

    print("\n" + "=" * 78)
    print("PHAN BO 7 NHOM (ok/404/no_run/no_jobs/no_log/download_error/parse_error)")
    print("=" * 78)
    for name in ("ok", "404", "no_run", "no_jobs", "no_log", "download_error", "parse_error"):
        print(f"  {name:16s}: {bucket_counts.get(name, 0)}")
    extra = {k: v for k, v in bucket_counts.items() if k not in
             ("ok", "404", "no_run", "no_jobs", "no_log", "download_error", "parse_error")}
    if extra:
        print("  (nhom la, chua khop 7 loai tren - KHONG bi bo sot, chi chua duoc xep):")
        for k, v in extra.items():
            print(f"    {k:30s}: {v}")

    print("\n  3 so tom tat (dung dung ten Bao yeu cau):")
    print(f"    selected              : {n_total}")
    print(f"    log_download_success  : {n_valid_zip}")
    print(f"    >=3 domains           : {n_with_3plus}")

    print("\n" + "=" * 78)
    print("PHAN LOAI CHI TIET HON (khong gop chung thanh 1 so, theo yeu cau audit)")
    print("=" * 78)
    print(f"  N repo thu (tested / selected)                : {n_total}")
    print(f"  N that bai o TANG GOI API /actions/runs      : {n_api_failed}  "
          f"<- KHAC voi 'khong co completed run', xem {RUN_DIR}/taskb_debug_raw_responses.log")
    print(f"  N genuinely KHONG co completed run gan day    : {n_no_run_genuine}")
    print(f"  N tim duoc completed run                      : {n_completed_found}")
    print(f"  N run KHONG co job nao tung chay (no_jobs)    : {n_no_jobs}  <- HOP LE, khong phai loi")
    print(f"  N log tai duoc (HTTP 200) = log_download_success : {n_log_downloadable}")
    print(f"  N zip hop le                                  : {n_valid_zip}")
    print(f"  N co >=1 URL trong log                        : {n_with_url}")
    print(f"  N co >=3 domain phan biet                     : {n_with_3plus}")
    print(f"  N log 403 (thieu quyen, ro rang)              : {n_log_403}")
    print(f"  N log 404, jobs_http cung loi (khong ro n_jobs): {n_log_404_suspicious_unknown_jobs}")
    print(f"  N log 404 thong thuong (run cu/khong ro tuoi)  : {n_log_404_ambiguous}")
    print(f"  N log 404 NHUNG jobs DA THAT SU chay (con mo,")
    print(f"             kho hieu hon truoc, can dieu tra)    : {n_no_log_jobs_ran}")
    print(f"  N request bi redirect 301/302 (repo doi ten/owner sau crawl)   : {n_redirect}")

    if n_no_log_jobs_ran > 0:
        print(f"\n  !! {n_no_log_jobs_ran} repo: job DA chay (xac nhan qua /jobs) nhung log VAN 404.")
        print(f"     Day la bi an THAT SU (khac voi no_jobs, khac voi 404 thong thuong) - can")
        print(f"     dieu tra tiep (retention rieng, xoa tay, gioi han to chuc rieng cho /logs).")

    if n_log_404_suspicious_unknown_jobs > 0:
        print(f"\n  !! {n_log_404_suspicious_unknown_jobs} repo tra 404 khi tai log, run con moi (<90 ngay),")
        print(f"     nhung KHONG xac dinh duoc n_jobs (/jobs cung loi). Xem cot run_age_days trong")
        print(f"     {RESULTS_CSV} va chay tay:")
        print(f"       gh api \"/repos/{{owner}}/{{repo}}/actions/runs/{{run_id}}/jobs\"")
        print(f"       gh api \"/repos/{{owner}}/{{repo}}/actions/runs/{{run_id}}/logs\" -i")

    if n_api_failed > 0:
        print(f"\n  !! CANH BAO: {n_api_failed}/{n_total} repo LOI O TANG GOI API - mau nay")
        print(f"     CHUA sach de ap dung quyet dinh Buoc 4. Sua nguyen nhan goi API that bai")
        print(f"     truoc (xem debug log), roi chay lai, KHONG dua ket luan tu con so hien tai.")

    print("\n" + "=" * 78)
    print("BUOC 4: QUYET DINH (tu dong ap dung nguong tu huong dan)")
    print("=" * 78)
    print(f"  Tong repo thu                          : {n_total}")
    print(f"  Tai duoc log (200 + zip hop le)         : {n_valid_zip} / {n_total}")
    print(f"  Co >=3 domain phan biet trong log       : {n_with_3plus} / {n_total}")
    print(f"  Repo co >=1 domain 'chi trong log'      : {n_with_gap} / {n_total}  "
          f"<- QUAN TRONG, xem chi tiet ben duoi")
    n_downloaded = n_valid_zip

    # NGUONG GOC cua thay tinh tren n=20 (>=15 tai duoc, >=10 co >=3 domain) -
    # tuc ty le >=75% va >=50%. Khi chay mau khac 20 (vd 11, 50), KHONG duoc
    # dung so tuyet doi 15/10 nguyen van - se sai (mau nho hon 20 luon "DUNG"
    # gia tao du ty le thanh cong cao, mau lon hon 20 luon de "DI" gia tao du
    # ty le thap). Quy doi ve TY LE, giu dung nguong 75%/50% cua thay, ap dung
    # duoc voi bat ky n_total nao.
    rate_downloaded = n_downloaded / n_total if n_total else 0
    rate_3plus = n_with_3plus / n_total if n_total else 0
    print(f"\n  (Quy doi ty le vi n_total={n_total} != 20: tai duoc {100*rate_downloaded:.0f}% "
          f"(nguong goc >=75%), co >=3 domain {100*rate_3plus:.0f}% (nguong goc >=50%))")

    if rate_downloaded >= 0.75 and rate_3plus >= 0.50:
        verdict = "DI"
        print(f"\n  >>> {n_downloaded}/{n_total} ({100*rate_downloaded:.0f}%) >= 75% VA "
              f"{n_with_3plus}/{n_total} ({100*rate_3plus:.0f}%) >= 50% "
              f"=> ✅ DI - mo rong mau (hoac len 200 repo neu day la mau cuoi).")
    elif rate_downloaded >= 0.50:
        verdict = "BO_TRO"
        print(f"\n  >>> Tai duoc nhung khong du ty le co >=3 domain "
              f"=> 🟡 BO TRO - dung cung probe S3, KHONG thay probe.")
    else:
        verdict = "DUNG"
        print(f"\n  >>> {n_downloaded}/{n_total} ({100*rate_downloaded:.0f}%) < 50% => ❌ DUNG - "
              f"chuyen sang probe (25 workflow S3 da co san trong s3_probe_candidates.json).")

    if n_total < 20:
        print(f"\n  !! LUU Y: n_total={n_total} < 20 (mau nho hon chuan cua thay) - verdict o tren")
        print(f"     CHI de tham khao xu huong, CHUA du tin cay de quyet dinh cuoi. Cho ket qua")
        print(f"     n=50 (dang chay) hoac n=20 tro len roi hang quyet dinh that.")

    print("\n  --- Domain 'CHI TRONG LOG' (workflow goi that nhung allowlist "
          "khong khai bao) ---")
    any_gap = False
    for r in rows_out:
        if r["domains_chi_trong_log"]:
            any_gap = True
            print(f"    {r['repo']}: {r['domains_chi_trong_log']}")
    if not any_gap:
        print("    (khong co repo nao trong mau nay - hoac chua co du lieu that)")

    out = {
        "dry_run": dry_run,
        "n_total_selected": n_total,
        "bucket_7": {name: bucket_counts.get(name, 0) for name in
                     ("ok", "404", "no_run", "no_jobs", "no_log", "download_error", "parse_error")},
        "bucket_unclassified": extra,
        "n_api_call_failed": n_api_failed,
        "n_no_run_genuine": n_no_run_genuine,
        "n_completed_run_found": n_completed_found,
        "n_no_jobs_run_never_executed": n_no_jobs,
        "n_log_downloadable_http200": n_log_downloadable,
        "n_valid_zip": n_valid_zip,
        "n_with_at_least_1_url": n_with_url,
        "n_with_3plus_domains": n_with_3plus,
        "n_log_403_permission": n_log_403,
        "n_log_404_ambiguous": n_log_404_ambiguous,
        "n_log_404_suspicious_unknown_jobs_status": n_log_404_suspicious_unknown_jobs,
        "n_no_log_despite_jobs_ran_SUSPICIOUS": n_no_log_jobs_ran,
        "n_redirect_301_302": n_redirect,
        "n_downloaded": n_downloaded,
        "n_with_at_least_1_domain_only_in_log": n_with_gap,
        "verdict": verdict,
        "verdict_reliable": n_api_failed == 0 and n_no_log_jobs_ran == 0 and n_log_404_suspicious_unknown_jobs == 0,
        "rows": rows_out,
        "note": (
            "R_log la CHAN DUOI cua R that (3 han che cau truc: recall lech theo "
            "cong cu in URL hay khong; redirect lam mat dich that; chi workflow DA "
            "CHAY moi co trong log) - moi domain trong R_log la BANG CHUNG DUONG "
            "chac chan, nhung thieu 1 domain trong log KHONG co nghia domain do "
            "khong can."
        ),
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Da ghi {OUT}")
    if dry_run:
        print("\n!! NHAC LAI: TOAN BO KET QUA O TREN LA DRY-RUN VOI DU LIEU GIA LAP !!")


if __name__ == "__main__":
    main()
