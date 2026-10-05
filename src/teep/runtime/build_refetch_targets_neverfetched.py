#!/usr/bin/env python3
"""
build_refetch_targets_neverfetched.py - mo rong refetch_targets.json them
59 repo CHUA TUNG fetch duoc log lan nao (khac voi 288 repo cua
build_refetch_targets.py - nhung repo DO da co log, chi la log SAI job).

Nguon: measurement/taskb_run_data/taskb_step1_results.csv (buoc fetch dau
tien), loc zip_ok!=true. Phan loai theo error_type xem co dang thu lai bang
API theo-workflow-file (taskb_refetch_correct_workflow.sh) hay khong:

  DANG THU LAI (co the la do script cu chi xem run GAN NHAT cua CA REPO, bo
  sot run THAT SU cua dung workflow block-mode nam sau trong danh sach):
    - no_jobs_run_never_executed (33): script cu duyet toi da 20 candidate/
      trang cua "run gan nhat toan repo" ma khong run nao co job that - neu
      workflow block-mode nam ngoai 20 candidate do (repo co nhieu workflow
      khac chay thuong xuyen hon), truy van THEO DUNG workflow file co the
      tim ra run that ma script cu bo sot.
    - log_200_but_invalid_zip (5): co the do dung nham run co job "skipped"
      loai khac chua duoc loc dung, thu lai voi endpoint moi de kiem tra.
    - download_error_api_runs_list_http404 / http000, log_http000 (5): loi
      tam thoi luc goi API (rate limit/mang) - thu lai co the qua.

  KHONG DANG THU LAI (da xac nhan KHONG the phuc hoi, bo qua):
    - log_http410 (12): HTTP 410 Gone - GitHub xac nhan RO RANG log da bi
      xoa vinh vien (khac 404 con mo ho), khong lien quan gi workflow nao.
    - no_run_genuine (4): API xac nhan 0 run "completed" nao TREN TOAN REPO
      (khong phai rieng 1 workflow) - repo chua tung chay Actions gi ca,
      thu lai theo workflow file cu the cung se ra 0.

OUTPUT: cap nhat measurement/experiment/refetch_targets.json (gop them, KHONG
ghi de cac repo da co tu build_refetch_targets.py).
"""
from teep import paths as _P
import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = _P.DATA_ROOT  # data root (was repo root via __file__)
STEP1_CSV = ROOT / "measurement" / "taskb_run_data" / "taskb_step1_results.csv"
POLICIES = ROOT / "data" / "policies_ci.jsonl"
TARGETS_JSON = ROOT / "measurement" / "experiment" / "refetch_targets.json"

RETRYABLE_ERROR_TYPES = {
    "no_jobs_run_never_executed",
    "log_200_but_invalid_zip",
    "download_error_api_runs_list_http404",
    "download_error_api_runs_list_http000",
    "log_http000",
}
NOT_RETRYABLE = {"log_http410", "no_run_genuine"}


def main():
    targets = json.loads(TARGETS_JSON.read_text(encoding="utf-8")) if TARGETS_JSON.exists() else {}
    n_already = len(targets)

    policies = [json.loads(l) for l in POLICIES.read_text(encoding="utf-8").splitlines() if l.strip()]
    block_files_by_repo = defaultdict(lambda: defaultdict(int))
    for row in policies:
        if row.get("egress_policy") == "block":
            fname = row["path"].split("/")[-1]
            block_files_by_repo[row["repo"]][fname] += 1

    n_retryable = 0
    n_not_retryable = 0
    n_no_block_file = 0
    with open(STEP1_CSV, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("zip_ok") == "true":
                continue
            repo = row["repo"]
            et = row.get("error_type", "")
            if repo in targets:
                continue  # da co trong danh sach 288 repo tu build_refetch_targets.py
            if et in NOT_RETRYABLE:
                n_not_retryable += 1
                continue
            if et not in RETRYABLE_ERROR_TYPES:
                continue  # error_type la doesn't khop nhom nao (khong nen xay ra, bo qua an toan)
            candidates = block_files_by_repo.get(repo, {})
            if not candidates:
                n_no_block_file += 1
                continue
            sorted_files = sorted(candidates.items(), key=lambda kv: -kv[1])
            targets[repo] = {
                "reason": f"never_fetched_{et}",
                "original_category": "not_in_step1_zip_ok",
                "workflow_name_previously_captured": "",
                "candidate_files": [fn for fn, _ in sorted_files],
            }
            n_retryable += 1

    TARGETS_JSON.write_text(json.dumps(targets, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Da co san (tu 288 repo truoc): {n_already}")
    print(f"Them moi (chua tung fetch duoc, co the thu lai): {n_retryable}")
    print(f"Khong the phuc hoi (410/no_run_genuine), khong them: {n_not_retryable}")
    print(f"Co error_type dang thu nhung khong co file block nao trong policies_ci.jsonl: {n_no_block_file}")
    print(f"TONG refetch_targets.json sau khi gop: {len(targets)}")
    print(f"Da ghi {TARGETS_JSON}")


if __name__ == "__main__":
    main()
