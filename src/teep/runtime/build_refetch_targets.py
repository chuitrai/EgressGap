#!/usr/bin/env python3
"""
build_refetch_targets.py - Task 5: chuan bi danh sach repo can fetch LAI +
DUNG workflow file can nham (thay vi "run completed gan nhat cua repo" nhu
taskb_fetch_and_grep.sh dang lam).

CAN CU: data/policies_ci.jsonl da co san, moi dong la 1 (repo, path, job) voi
egress_policy tinh TU TINH (doc file YAML, khong phai runtime) - repo nao co
>=1 dong egress_policy=="block" cho biet CHINH XAC file workflow nao
(.github/workflows/<ten>.yml) thuc su enforce Harden-Runner block.

taskb_fetch_and_grep.sh (buoc 1) lai goi API chung
  GET /repos/{repo}/actions/runs?per_page=5
lay run "completed" GAN NHAT cua CA REPO, khong loc theo workflow file - neu
workflow gan nhat chay KHONG PHAI 1 trong cac file block-enforced kia thi log
thu duoc sai hoan toan (xac nhan qua audit_log_validity.py: 45.9% corpus roi
vao truong hop nay - 24.5% khong co bang chung Harden-Runner nao, 16.9% bat
duoc dung job Harden-Runner nhung la job audit-mode trong khi repo CO san job
block-mode khac, 4.5% bat dung job block nhung runtime tu fallback audit).

GitHub co API rieng loc THEO 1 WORKFLOW FILE CU THE (khong phai toan repo):
  GET /repos/{repo}/actions/workflows/{file_name}/runs?per_page=5&status=completed
(file_name la ten file, vd "ci.yml" - KHONG can prefix ".github/workflows/").
Day la fix dung goc: chon dung workflow TRUOC KHI goi API, thay vi loc hau ky
sau khi da tai nham log.

OUTPUT: measurement/experiment/refetch_targets.json
  { repo: { reason: "...", candidate_files: ["ci.yml", "release.yml", ...] } }
  candidate_files sap theo SO LUONG job egress_policy=block trong file do,
  giam dan (uu tien file co nhieu job block nhat truoc).

CHI tao danh sach - KHONG tu goi GitHub API (sandbox nay bi chan mang toi
api.github.com, xem memory "Sandbox blocks GitHub API"). Ban chay that
(taskb_refetch_correct_workflow.sh) phai chay tren may cua Bao.
"""
from teep import paths as _P
import json
from collections import defaultdict
from pathlib import Path

ROOT = _P.DATA_ROOT  # data root (was repo root via __file__)
POLICIES = ROOT / "data" / "policies_ci.jsonl"
AUDIT_JSON = ROOT / "measurement" / "experiment" / "log_validity_audit.json"
OUT = ROOT / "measurement" / "experiment" / "refetch_targets.json"

NEEDS_REFETCH_CATEGORIES = {
    "A_no_hr_evidence_CONTAMINATION_RISK": "wrong_job_no_hr_evidence",
    "C_declared_audit_no_enforcement": "wrong_job_audit_mode_but_block_available",
    "B_block_declared_but_fallback_to_audit": "correct_job_but_runtime_fallback_recheck",
    "E_hr_present_no_clear_config_line": "unclear_needs_recheck",
}


def main():
    audit = json.loads(AUDIT_JSON.read_text(encoding="utf-8"))
    policies = [json.loads(l) for l in POLICIES.read_text(encoding="utf-8").splitlines() if l.strip()]

    block_files_by_repo = defaultdict(lambda: defaultdict(int))
    for row in policies:
        if row.get("egress_policy") == "block":
            fname = row["path"].split("/")[-1]
            block_files_by_repo[row["repo"]][fname] += 1

    targets = {}
    n_no_block_file_found = 0
    for repo, info in audit["per_repo"].items():
        cat = info.get("category")
        if cat not in NEEDS_REFETCH_CATEGORIES:
            continue
        candidates = block_files_by_repo.get(repo, {})
        if not candidates:
            # repo duoc chon vao corpus vi co harden-runner nhung khong co
            # dong egress_policy==block nao trong policies_ci.jsonl - hoac
            # policies_ci.jsonl chi ghi audit cho repo nay (nen khong the
            # "sua" bang cach doi workflow, R_exec cua repo nay von di chi
            # do duoc voi audit-mode). Ghi lai rieng de khong lam nhu con
            # sua duoc.
            n_no_block_file_found += 1
            continue
        sorted_files = sorted(candidates.items(), key=lambda kv: -kv[1])
        targets[repo] = {
            "reason": NEEDS_REFETCH_CATEGORIES[cat],
            "original_category": cat,
            "workflow_name_previously_captured": info.get("workflow_name_selected_by_fetch_script", ""),
            "candidate_files": [f for f, _ in sorted_files],
        }

    OUT.write_text(json.dumps(targets, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Tong repo can fetch lai (co it nhat 1 file block-enforced de nham lai): {len(targets)}")
    print(f"Repo KHONG sua duoc bang cach nay (khong co file egress_policy=block nao trong policies_ci.jsonl): {n_no_block_file_found}")
    by_reason = defaultdict(int)
    for v in targets.values():
        by_reason[v["reason"]] += 1
    for reason, n in sorted(by_reason.items()):
        print(f"  {reason}: {n}")
    print(f"Da ghi {OUT}")


if __name__ == "__main__":
    main()
