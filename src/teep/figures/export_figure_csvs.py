#!/usr/bin/env python3
r"""
export_figure_csvs.py - Xuat 2 CSV mà make_figures.py cần, TỪ DỮ LIỆU THẬT.

make_figures.py đọc:
    data/cotenant_per_policy.csv   policy_id,cotenant_before,cotenant_after
    data/destination_freq.csv      destination,n_repos
nhưng KHÔNG script nào sinh ra chúng -> chạy make_figures.py báo "missing input".
File này lấp đúng khoảng đó, từ output pipeline đã có (KHÔNG tạo số mới):

    cotenant_per_policy.csv  <- measurement/tighten_full_corpus.json["rows"]
        policy_id = repo|path|job ; cotenant_before = reach_before ;
        cotenant_after = reach_after  (|reach(I)| / |reach(I')| theo shared-IP,
        chính là "co-tenant names reachable" ở Fig 2b)
    destination_freq.csv     <- measurement/domain_frequency_buckets.json
        flatten 4 bucket (">400","50-400","5-50","<5") -> destination,n_repos
        (tong phai = 1803 domain)

CHẠY (từ thư mục gốc code/, giống các script measurement khác):
    python results/export_figure_csvs.py
Rồi: python results/make_figures.py

SANITY tự in ra để đối chiếu bài (lệch là DỪNG, đừng sửa số cho khớp hình):
    - n policy, median/max reach before/after  -> phải khớp 7 / 6,307 và 3 / 313
      (LƯU Ý: make_figures Fig 2b lọc co-tenant>0; script này in CẢ hai cách
       — median trên toàn bộ VÀ median trên subset >0 — để biết 7/3 của Bảng I
       được tính trên quần thể nào. Dùng đúng con số khớp Bảng I.)
    - n destination (=1803), % <5 repo (=84.0%)
"""
import csv
import json
import statistics as st
from pathlib import Path

from teep import paths as _P
MEAS = _P.data("measurement")
DATA = _P.data("data")
DATA.mkdir(exist_ok=True)


def export_cotenant():
    src = MEAS / "tighten_full_corpus.json"
    rows = json.loads(src.read_text(encoding="utf-8"))["rows"]
    out = DATA / "cotenant_per_policy.csv"
    before_all, after_all = [], []
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["policy_id", "cotenant_before", "cotenant_after"])
        for r in rows:
            pid = f'{r["repo"]}|{r.get("path","")}|{r.get("job","")}'
            b = int(r.get("reach_before", 0))
            a = int(r.get("reach_after", 0))
            w.writerow([pid, b, a])
            before_all.append(b)
            after_all.append(a)

    bpos = [x for x in before_all if x > 0]
    apos = [x for x in after_all if x > 0]
    print(f"[cotenant] {len(before_all)} policy -> {out}")
    print(f"  median reach  (ALL)   before={st.median(before_all):.0f}  after={st.median(after_all):.0f}")
    print(f"  median reach  (>0)    before={st.median(bpos):.0f}  after={st.median(apos):.0f}")
    print(f"  max reach             before={max(before_all)}  after={max(after_all)}")
    print(f"  -> doi chieu Bang I: median 7/3, max 6,307/313. Chon quan the median khop Bang I.")


def export_destination_freq():
    src = MEAS / "domain_frequency_buckets.json"
    d = json.loads(src.read_text(encoding="utf-8"))
    out = DATA / "destination_freq.csv"
    n_total_expected = d.get("n_domain_total")
    rows = []
    for key in (">400", "50-400", "5-50", "<5"):
        for item in d.get(key, []):
            rows.append((item["domain"], int(item["n_repo"])))
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["destination", "n_repos"])
        w.writerows(rows)

    n = len(rows)
    share_lt5 = 100 * sum(1 for _, c in rows if c < 5) / n if n else 0
    print(f"[destfreq] {n} destination -> {out}")
    print(f"  n_domain_total trong file = {n_total_expected}  (phai = {n})")
    print(f"  % <5 repo = {share_lt5:.1f}%  -> doi chieu bai: 1,803 va 84.0%")
    if n_total_expected and n != n_total_expected:
        print(f"  [!] LECH: flatten {n} != n_domain_total {n_total_expected} - kiem lai bucket keys.")


if __name__ == "__main__":
    export_cotenant()
    print()
    export_destination_freq()
