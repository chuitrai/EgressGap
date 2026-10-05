#!/usr/bin/env python3
"""
quantify_test_repo_noise.py - Thieu 2 (review): dinh luong nhieu tu repo
test/adversarial/connectivity-check trong 1.262 dong PARAMETRIC, thay vi chi
"nhan ra co van de" ma khong dem.

TIEU CHI NHIEU (2 loai, dem rieng va dem hop):
  A. Repo thuoc he sinh thai step-security tu test chinh no:
     step-security/*, step-integration-tests/*, actions-marketplace-validations/*
  B. Ten workflow (path) chua tu khoa: connectivity, test, goat (khong phan biet hoa/thuong)

CHAY
    uv run python measurement/quantify_test_repo_noise.py
"""
from teep import paths as _P
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TARGETS = Path(str(_P.data("measurement/parametric_targets.json")))
OUT = Path(str(_P.data("measurement/test_repo_noise_report.json")))

# v2 (mo rong sau khi doi chieu allowlist lo ra 2 IP literal + 1 domain base32 tu
# "step-security-demo/harden-runner-demo" va "step-security-experiments/canary-tls"
# - KHONG nam trong prefix ban dau vi khac ten to chuc GitHub. Doi sang regex bat
# CHUOI CON "harden-runner"/"step-security" bat ky dau trong "owner/repo", vi day
# la dac diem chung cua moi bien the demo/poc/test cua chinh cong cu Harden-Runner
# (da thay qua vi du: step-security-demo/*, step-security-experiments/*,
# step-security-poc/*, harden-runner-canary/*, raysubham/harden-runner-test,
# rohan-stepsecurity/*, actions-marketplace-validations/step-security_*).
REPO_NOISE_RE = re.compile(r"harden-?runner|step-?security|arm-int-test", re.IGNORECASE)
WORKFLOW_KEYWORDS = re.compile(r"connectivity|test|goat|exfil|canary|poc", re.IGNORECASE)


def is_noise_repo(repo):
    return bool(REPO_NOISE_RE.search(repo))


def is_noise_workflow(workflow):
    return bool(WORKFLOW_KEYWORDS.search(workflow))


def main():
    data = json.loads(TARGETS.read_text(encoding="utf-8"))
    rows = data["rows"]
    total = len(rows)

    noise_repo = [r for r in rows if is_noise_repo(r["repo"])]
    noise_workflow = [r for r in rows if is_noise_workflow(r["workflow"])]
    noise_either_idx = {
        i for i, r in enumerate(rows)
        if is_noise_repo(r["repo"]) or is_noise_workflow(r["workflow"])
    }
    noise_either = [rows[i] for i in noise_either_idx]
    clean_rows = [r for i, r in enumerate(rows) if i not in noise_either_idx]

    def repo_set(rs):
        return sorted({r["repo"] for r in rs})

    out = {
        "summary": {
            "total_lines": total,
            "n_lines_noise_repo_prefix": len(noise_repo),
            "pct_noise_repo_prefix": round(100 * len(noise_repo) / total, 1),
            "n_lines_noise_workflow_keyword": len(noise_workflow),
            "pct_noise_workflow_keyword": round(100 * len(noise_workflow) / total, 1),
            "n_lines_noise_either": len(noise_either),
            "pct_noise_either": round(100 * len(noise_either) / total, 1),
            "n_lines_clean": total - len(noise_either),
            "pct_clean": round(100 * (total - len(noise_either)) / total, 1),
        },
        "repos_flagged_by_prefix": repo_set(noise_repo),
        "repos_flagged_by_workflow_keyword": repo_set(noise_workflow),
        "resolution_breakdown_noise_vs_clean": {
            "noise": {
                res: sum(1 for r in noise_either if r["resolution"] == res)
                for res in ("RESOLVED", "UNRESOLVED", "SCRIPT_REFERENCE")
            },
            "clean": {
                res: sum(1 for r in clean_rows if r["resolution"] == res)
                for res in ("RESOLVED", "UNRESOLVED", "SCRIPT_REFERENCE")
            },
        },
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    s = out["summary"]
    print("=" * 78)
    print(f"NHIEU TU REPO TEST/ADVERSARIAL trong {total} dong PARAMETRIC")
    print("=" * 78)
    print(f"  Repo prefix step-security/* etc.   : {s['n_lines_noise_repo_prefix']:>5}  ({s['pct_noise_repo_prefix']}%)")
    print(f"  Workflow ten chua connectivity/test/goat: {s['n_lines_noise_workflow_keyword']:>5}  ({s['pct_noise_workflow_keyword']}%)")
    print(f"  HOP (repo HOAC workflow)            : {s['n_lines_noise_either']:>5}  ({s['pct_noise_either']}%)")
    print(f"  Con lai (\"sach\")                    : {s['n_lines_clean']:>5}  ({s['pct_clean']}%)")
    print()
    print(f"  So repo bi flag boi prefix: {len(out['repos_flagged_by_prefix'])}")
    for r in out["repos_flagged_by_prefix"]:
        print(f"    {r}")
    print()
    if s['pct_noise_either'] > 10:
        print(f"  !! {s['pct_noise_either']}% > nguong 10% -> CAN phien ban da loc cho moi con so !!")
    else:
        print(f"  {s['pct_noise_either']}% <= nguong 10% -> chua bat buoc phai loc, nhung nen bao cao rieng.")
    print(f"\n  Da ghi {OUT}")


if __name__ == "__main__":
    main()
