#!/usr/bin/env python3
"""
audit_log_validity.py - Task 0 (Plan B): do ty le 2 rui ro validity tren TOAN
BO corpus da fetch (khong chi 5 repo audit tay truoc do).

Rui ro (a) "wrong-job contamination": taskb_fetch_and_grep.sh CHU DICH chon
"run completed gan nhat" cua repo, KHONG loc theo workflow_name - neu run gan
nhat nhat thuoc ve 1 workflow/feature khac hoan toan voi workflow co
step-security/harden-runner (vd GitHub Copilot Code Review, CodeQL default
setup - ca hai KHONG duoc backing boi file .github/workflows/*.yml nen khong
bao gio chua chuoi "harden-runner"), log thu duoc se KHONG co bang chung
Harden-Runner nao ca -> R_exec=∅ GIA (khong phai vi repo khong dependency nao,
ma vi log sai job hoan toan).

Rui ro (b) "audit-mode silent fallback": Harden-Runner buoc pre-step tu fetch
policy cache co the loi (vd "Unable to fetch cacheURL"), khi do TU DONG
"Switching egress-policy to audit mode" - dinh nghia la block nhung THUC TE
runtime la audit (khong enforce). Audit tay 5 repo phat hien 2/3 log co
Harden-Runner la truong hop nay (madnuttah/unbound-docker, DataDog/KubeHound);
repo thu 3 (GoogleForCreators/web-stories-wp) khai bao SAN la audit (khong
phai fallback tu block - van la 1 dang "khong enforce" nhung khac co che).

CHI doc file, KHONG chay lai pipeline extract_rlog_v2.py/build_d_static.py.

OUTPUT:
  measurement/experiment/log_validity_audit.json   (per-repo classification)
  In ra bao cao tong hop ra stdout.
"""
from teep import paths as _P
import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = _P.DATA_ROOT  # data root (was repo root via __file__)
LOGS_DIR = ROOT / "measurement" / "taskb_run_data" / "logs"
SELECTED_JSON = ROOT / "measurement" / "taskb_selected_repos.json"
STEP1_CSV = ROOT / "measurement" / "taskb_run_data" / "taskb_step1_results.csv"
OUT = ROOT / "measurement" / "experiment" / "log_validity_audit.json"

HR_EVIDENCE_RE = re.compile(r"harden-runner|step-security", re.I)
FALLBACK_RE = re.compile(r"Switching egress-policy to audit mode", re.I)
# BUG tu phat hien khi chay lan dau: dong log GitHub Actions co dang
# "<timestamp>   egress-policy: block" TREN CUNG 1 DONG (khong xuong dong
# truoc "egress-policy:") - regex neo ^ truoc dau cham cau bi sai khien 70.9%
# repo roi vao nhom "khong ro". Sua: chi can tim cum "egress-policy: <x>" o
# BAT KY DAU nao trong dong, khong neo dau dong. An toan voi dong fallback
# "Switching egress-policy TO audit mode" vi cum do la "egress-policy to
# audit" (khong co dau ":"), khong khop pattern "egress-policy:\s*audit".
DECLARED_BLOCK_RE = re.compile(r"egress-policy:\s*block\b", re.I)
DECLARED_AUDIT_RE = re.compile(r"egress-policy:\s*audit\b", re.I)
CACHE_FETCH_FAIL_RE = re.compile(r"Unable to fetch cacheURL", re.I)


def load_workflow_names():
    """repo -> workflow_name da chon boi taskb_fetch_and_grep.sh (tu CSV Buoc 1)."""
    m = {}
    if not STEP1_CSV.exists():
        return m
    with open(STEP1_CSV, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            m[row["repo"]] = row.get("workflow_name", "")
    return m


def classify_repo(extracted_dir):
    """Doc TOAN BO file .txt trong extracted/ cua 1 repo, tra ve dict phan loai."""
    all_text_parts = []
    for txt_file in sorted(extracted_dir.rglob("*.txt")):
        try:
            all_text_parts.append(txt_file.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    text = "\n".join(all_text_parts)

    hr_present = bool(HR_EVIDENCE_RE.search(text))
    fallback_present = bool(FALLBACK_RE.search(text))
    declared_block = bool(DECLARED_BLOCK_RE.search(text))
    declared_audit = bool(DECLARED_AUDIT_RE.search(text))
    cache_fail = bool(CACHE_FETCH_FAIL_RE.search(text))

    if not hr_present:
        category = "A_no_hr_evidence_CONTAMINATION_RISK"
    elif fallback_present:
        category = "B_block_declared_but_fallback_to_audit"
    elif declared_audit and not declared_block:
        category = "C_declared_audit_no_enforcement"
    elif declared_block and not fallback_present:
        category = "D_declared_block_no_fallback_detected_GOOD"
    else:
        # co bang chung HR (vd *.stepsecurity.io domain, hoac dong log khac
        # nhac "harden-runner") nhung khong tim thay dong config
        # "egress-policy: <x>" ro rang trong text da doc - can xem tay.
        category = "E_hr_present_no_clear_config_line"

    return {
        "category": category,
        "hr_evidence_present": hr_present,
        "declared_block": declared_block,
        "declared_audit": declared_audit,
        "runtime_fallback_to_audit": fallback_present,
        "cache_fetch_failed": cache_fail,
        "n_txt_files": len(all_text_parts),
    }


def main():
    selected = json.loads(SELECTED_JSON.read_text(encoding="utf-8"))["selected"]
    selected_repos = {c["repo"] for c in selected}
    workflow_names = load_workflow_names()

    safe_to_real = {}
    for r in selected_repos:
        safe_to_real[r.replace("/", "_")] = r
        safe_to_real[r.replace("/", "__")] = r  # taskb_fetch_and_grep.sh dung "__"

    per_repo = {}
    n_no_extracted = 0
    counts = Counter()

    for repo_dir in sorted(LOGS_DIR.iterdir()):
        if not repo_dir.is_dir():
            continue
        extracted = repo_dir / "extracted"
        repo = safe_to_real.get(repo_dir.name, repo_dir.name.replace("_", "/", 1))
        if repo not in selected_repos:
            # thu ca 2 kieu thay the "_" de khop dung ten that (ten repo/org co
            # the tu chua "_" nen khong doan nguoc chinh xac 100% - bo qua neu
            # khong khop repo nao trong danh sach 609 da chon)
            continue
        if not extracted.exists():
            n_no_extracted += 1
            per_repo[repo] = {"category": "Z_no_extracted_dir", "workflow_name": workflow_names.get(repo, "")}
            counts["Z_no_extracted_dir"] += 1
            continue
        info = classify_repo(extracted)
        info["workflow_name_selected_by_fetch_script"] = workflow_names.get(repo, "")
        per_repo[repo] = info
        counts[info["category"]] += 1

    n_total_selected = len(selected_repos)
    n_with_logs = n_total_selected - n_no_extracted

    print("=" * 70)
    print(f"Task 0 - Audit validity toan corpus ({n_total_selected} repo da chon)")
    print("=" * 70)
    print(f"Khong co thu muc extracted/ (chua fetch duoc log)   : {n_no_extracted}")
    print(f"Co log de phan tich                                 : {n_with_logs}")
    print()
    print("Phan loai (chi tinh tren {} repo CO log):".format(n_with_logs))
    for cat in sorted(counts):
        if cat == "Z_no_extracted_dir":
            continue
        n = counts[cat]
        pct = 100.0 * n / n_with_logs if n_with_logs else 0
        print(f"  {cat:50s} : {n:4d}  ({pct:5.1f}%)")
    print()

    n_contam = counts["A_no_hr_evidence_CONTAMINATION_RISK"]
    n_fallback = counts["B_block_declared_but_fallback_to_audit"]
    n_declared_audit = counts["C_declared_audit_no_enforcement"]
    n_good = counts["D_declared_block_no_fallback_detected_GOOD"]
    n_unclear = counts["E_hr_present_no_clear_config_line"]

    print("-" * 70)
    print("TOM TAT RUI RO:")
    print(f"  (a) Nghi ngo sai job (khong co bang chung HR nao)  : {n_contam}/{n_with_logs} = {100*n_contam/n_with_logs:.1f}%")
    print(f"  (b) Block khai bao nhung fallback audit lam runtime: {n_fallback}/{n_with_logs} = {100*n_fallback/n_with_logs:.1f}%")
    print(f"  (c) Khai bao san la audit (khong enforce tu dau)   : {n_declared_audit}/{n_with_logs} = {100*n_declared_audit/n_with_logs:.1f}%")
    print(f"  Block THAT SU duoc enforce (khong fallback)        : {n_good}/{n_with_logs} = {100*n_good/n_with_logs:.1f}%")
    print(f"  Khong ro (co bang chung HR nhung khong thay dong config) : {n_unclear}/{n_with_logs} = {100*n_unclear/n_with_logs:.1f}%")
    print()
    print(f"  => Tong so repo co R_exec KHONG dai dien cho 'block that su duoc enforce'")
    print(f"     (a + b + c) = {n_contam + n_fallback + n_declared_audit}/{n_with_logs} = "
          f"{100*(n_contam + n_fallback + n_declared_audit)/n_with_logs:.1f}%")

    print()
    print("-" * 70)
    print(f"Vi du 10 repo thuoc nhom (a) 'khong co bang chung HR' (workflow_name da chon):")
    shown = 0
    for repo, info in per_repo.items():
        if info.get("category") == "A_no_hr_evidence_CONTAMINATION_RISK":
            wf = info.get("workflow_name_selected_by_fetch_script", "")
            print(f"  {repo}  <- workflow captured: {wf!r}")
            shown += 1
            if shown >= 10:
                break

    OUT.write_text(json.dumps({
        "n_total_selected": n_total_selected,
        "n_no_extracted": n_no_extracted,
        "n_with_logs": n_with_logs,
        "counts": dict(counts),
        "per_repo": per_repo,
    }, indent=1, ensure_ascii=False), encoding="utf-8")
    print()
    print(f"Da ghi chi tiet tung repo vao {OUT}")


if __name__ == "__main__":
    main()
