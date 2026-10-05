"""
recheck_same_30.py - Doi soat CHINH XAC 30 mau (repo, domain) da kiem tra tay truoc do
(random.seed(42), khong random lai) duoi extractor moi (extract_rlog_v2.py), de ra bang
before/after: nhan xet tay cu (REAL/TEXT/AMBIGUOUS) vs ket qua tu dong moi (WORKLOAD/
TOOLING/ABSENT). Muc dich: chung minh extractor moi khong "tinh co dung" ma la fix that.
"""
from teep import paths as _P
import json
from pathlib import Path

random_seed_pairs = None
import random
random.seed(42)
RLOG_OLD = json.loads(Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls.json"))).read_text(encoding="utf-8"))
pairs = []
for repo, entries in RLOG_OLD.items():
    for e in entries:
        pairs.append((repo, e["domain"]))
sample = random.sample(pairs, 30)  # DUNG lai seed 42 + cung ham random.sample -> ra dung 30 cap cu

# ket qua tay da phan loai truoc (REAL / TEXT / AMBIGUOUS) theo dung thu tu in ra
# DUNG DUNG 7 REAL / 17 TEXT / 6 AMBIGUOUS da bao cao truoc do (khong doi lai)
manual_before = [
    "TEXT", "AMBIGUOUS", "REAL", "TEXT", "TEXT", "TEXT", "REAL",
    "TEXT", "TEXT", "TEXT", "TEXT", "REAL", "TEXT", "AMBIGUOUS",
    "AMBIGUOUS", "TEXT", "REAL", "REAL", "REAL", "AMBIGUOUS", "TEXT",
    "TEXT", "REAL", "TEXT", "TEXT", "AMBIGUOUS", "TEXT", "TEXT", "TEXT", "AMBIGUOUS",
]
assert manual_before.count("REAL") == 7 and manual_before.count("TEXT") == 17 and manual_before.count("AMBIGUOUS") == 6

RLOG_V2 = json.loads(Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json"))).read_text(encoding="utf-8"))

print(f"{'#':<3}{'repo':<48}{'domain':<45}{'before':<16}{'AFTER (v2)'}")
counts_after = {"WORKLOAD": 0, "TOOLING": 0, "ABSENT": 0}
for i, ((repo, domain), before) in enumerate(zip(sample, manual_before), 1):
    entries = RLOG_V2.get(repo, [])
    match = next((e for e in entries if e["domain"] == domain.lower()), None)
    if match:
        after = f"{match['classification']} ({match['evidence']}, exe={match['exe']})"
        counts_after[match["classification"]] += 1
    else:
        after = "KHONG con trong R_log (loai dung, khong co bang chung DNS)"
        counts_after["ABSENT"] += 1
    print(f"{i:<3}{repo[:46]:<48}{domain[:43]:<45}{before:<16}{after}")

print("\n--- tom tat AFTER ---")
print(counts_after)
