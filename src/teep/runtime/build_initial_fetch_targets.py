#!/usr/bin/env python3
"""
build_initial_fetch_targets.py - hop nhat 1 danh sach fetch cho MOI repo trong
taskb_selected_repos.json (ban MOI, sau khi hr_crawl mo rong corpus) ma HIEN
CHUA co thu muc extracted/ - bao gom CA 2 nhom cung luc, khong can biet truoc
Bao da chay xong batch nao:
  (1) repo hoan toan MOI (vua xuat hien do hr_crawl/taskb_select_repos --all
      mo rong corpus, chua tung duoc fetch lan nao).
  (2) repo CU trong 609 nhung van con thieu extracted/ (vd batch 41-repo
      "never fetched" chua chay, hoac chay roi van that bai).

Dung CHUNG 1 co che voi Task 5 (nham dung workflow file ngay tu dau, khong
dung API chung chung /actions/runs cua ca repo) - tranh lap lai dung bug
"bat sai job" da phat hien tren 45,9% corpus cu.

OUTPUT: gop them vao measurement/experiment/refetch_targets.json (KHONG dong
lai file cu - repo da co san trong do, kem ca repo da fetch THANH CONG boi
cac batch truoc, se KHONG bi dong lai vi script nay chi kiem tra dia that,
khong quan tam file JSON cu ghi gi).
"""
from teep import paths as _P
import json
from collections import defaultdict
from pathlib import Path

ROOT = _P.DATA_ROOT  # data root (was repo root via __file__)
SELECTED_JSON = ROOT / "measurement" / "taskb_selected_repos.json"
POLICIES = ROOT / "data" / "policies_ci.jsonl"
LOGS_DIR = ROOT / "measurement" / "taskb_run_data" / "logs"
TARGETS_JSON = ROOT / "measurement" / "experiment" / "refetch_targets.json"


def main():
    selected = json.loads(SELECTED_JSON.read_text(encoding="utf-8"))["selected"]
    selected_repos = [c["repo"] for c in selected]
    print(f"Tong repo trong taskb_selected_repos.json (ban hien tai): {len(selected_repos)}")

    policies = [json.loads(l) for l in POLICIES.read_text(encoding="utf-8").splitlines() if l.strip()]
    block_files_by_repo = defaultdict(lambda: defaultdict(int))
    for row in policies:
        if row.get("egress_policy") == "block":
            fname = row["path"].split("/")[-1]
            block_files_by_repo[row["repo"]][fname] += 1

    targets = json.loads(TARGETS_JSON.read_text(encoding="utf-8")) if TARGETS_JSON.exists() else {}
    n_already_have_logs = 0
    n_added_new = 0
    n_no_block_file = 0
    n_already_in_targets = 0

    for repo in selected_repos:
        safe_repo = repo.replace("/", "_")
        extracted_dir = LOGS_DIR / safe_repo / "extracted"
        if extracted_dir.exists() and any(extracted_dir.rglob("*.txt")):
            n_already_have_logs += 1
            continue  # da co log that (>=1 file .txt) - khong can fetch nua o day
        if repo in targets:
            n_already_in_targets += 1
            continue  # da nam trong hang cho cua 1 lan build truoc, khong ghi de
        candidates = block_files_by_repo.get(repo, {})
        if not candidates:
            n_no_block_file += 1
            continue
        sorted_files = sorted(candidates.items(), key=lambda kv: -kv[1])
        targets[repo] = {
            "reason": "initial_fetch_new_or_still_missing",
            "original_category": "no_extracted_dir_on_disk",
            "workflow_name_previously_captured": "",
            "candidate_files": [fn for fn, _ in sorted_files],
        }
        n_added_new += 1

    TARGETS_JSON.write_text(json.dumps(targets, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Da co log that tren dia (bo qua, khong can fetch)      : {n_already_have_logs}")
    print(f"Da nam san trong refetch_targets.json tu truoc         : {n_already_in_targets}")
    print(f"Them moi vao hang cho fetch (repo moi hoac con thieu)  : {n_added_new}")
    print(f"Khong co file block-mode nao trong policies_ci.jsonl   : {n_no_block_file}")
    print(f"TONG refetch_targets.json sau khi gop                  : {len(targets)}")
    print(f"Da ghi {TARGETS_JSON}")


if __name__ == "__main__":
    main()
