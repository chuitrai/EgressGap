#!/usr/bin/env python3
"""
rank_s3_probe_candidates.py - Buoc 4: 226 dong UNRESOLVED (+10 SCRIPT_REFERENCE
bi loai) khong dua het vao S3 mot cach may moc. Aggregate theo (repo, workflow,
job) + reason_category, rank theo uu tien nguyen nhan (network-relevance) x tan
suat x da dang repo (diversity), chon top N lam candidate probe.

SO THUC TE (sau khi sua bug #4 + #5 + retry chunk loi + doi chieu noise - xem
parametric_extraction_notes.md muc 0/0.4): tong 1.262 dong PARAMETRIC. RESOLVED
1.026 (81,3%), UNRESOLVED 226 (17,9%), SCRIPT_REFERENCE 10 (0,8%). Trong 236 dong
khong-RESOLVED, phan theo reason_category: nested_command 110 (46,6%),
parser_extraction_failure 76 (32,2%), dynamic_variable_expression 26 (11,0%),
complex_syntax_or_malformed 14 (5,9%), local_reference 10 (4,2%).

QUAN TRONG - LOC NHIEU REPO TU-TEST (xem quantify_test_repo_noise.py):
78,0% cua TOAN BO corpus PARAMETRIC (984/1.262 dong) la tu 12 repo/workflow
demo-poc-canary cua chinh he sinh thai step-security (vd. step-security-demo/
harden-runner-demo, step-security-experiments/canary-tls, ...). O ban truoc
(chua loc), cac repo nay chiem nhieu vi tri trong top-25 S3 probe - vo nghia
vi day la du lieu demo tu-tao, khong phai nhu cau build that. Script nay GIO
LOAI HOAN TOAN is_test_repo_noise=true khoi tap candidate xep hang (khong chi
ha uu tien) - danh sach top-N chi con repo "sach".

VI SAO KHONG PROBE TAT CA 226
    - "local_reference" (SCRIPT_REFERENCE, 10 dong): duong dan local, KHONG
      phai network call -> loai hoan toan, probe khong co y nghia.
    - "parser_extraction_failure" (76 dong): domain THUONG LA tinh duoc (rule
      Semgrep chi chua phu), khong phai gioi han that cua static analysis ->
      uu tien THAP, vi sua extractor re hon ton 1 probe S3.
    - "dynamic_variable_expression" (26 dong) va "nested_command" (110 dong):
      day moi la nhung truong hop GENUINELY khong the biet truoc tinh - CAN S3
      that su de quan sat runtime -> uu tien CAO.

CACH RANK
    priority(reason_category) x frequency(so dong trong policy) , sau do greedy
    chon da dang repo (khong lay qua nhieu candidate tu cung 1 repo o vong dau).
    Chi rank tren tap da loai is_test_repo_noise (xem tren).

CHAY
    uv run python measurement/rank_s3_probe_candidates.py
"""
from teep import paths as _P
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

pass  # sys.path hack removed: package imports via teep.*
from teep.scoping.quantify_test_repo_noise import is_noise_repo, is_noise_workflow  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TARGETS = Path(str(_P.data("measurement/parametric_targets.json")))
OUT = Path(str(_P.data("measurement/s3_probe_candidates.json")))
TOP_N = 25

REASON_PRIORITY = {
    "dynamic_variable_expression": 3,
    "nested_command": 2,
    "parser_extraction_failure": 1,
    "complex_syntax_or_malformed": 1,
}
EXCLUDED_REASONS = {"local_reference"}  # SCRIPT_REFERENCE - khong phai network call


def _is_noise(r):
    return r.get("is_test_repo_noise") or is_noise_repo(r["repo"]) or is_noise_workflow(r["workflow"])


def main():
    data = json.loads(TARGETS.read_text(encoding="utf-8"))
    all_nonresolved = [
        r for r in data["rows"]
        if r["resolution"] != "RESOLVED" and r["reason_category"] not in EXCLUDED_REASONS
    ]
    n_noise_excluded = sum(1 for r in all_nonresolved if _is_noise(r))
    rows = [r for r in all_nonresolved if not _is_noise(r)]
    print(f"Tong dong khong-resolve (sau khi loai local_reference): {len(all_nonresolved)}")
    print(f"  Trong do la nhieu repo tu-test (is_test_repo_noise): {n_noise_excluded} -> LOAI KHOI RANKING")
    print(f"  Con lai de rank (sach): {len(rows)}")

    grouped = defaultdict(lambda: {"lines": [], "reasons": Counter(), "tools": set()})
    for r in rows:
        key = (r["repo"], r["workflow"], r["job"])
        g = grouped[key]
        g["lines"].append(r["raw_line"])
        g["reasons"][r["reason_category"]] += 1
        g["tools"].add(r["tool"])

    candidates = []
    for key, g in grouped.items():
        repo, workflow, job = key
        frequency = len(g["lines"])
        priority = max(REASON_PRIORITY.get(rc, 0) for rc in g["reasons"])
        dominant_reason = g["reasons"].most_common(1)[0][0]
        score = priority * frequency
        candidates.append({
            "repo": repo, "workflow": workflow, "job": job,
            "frequency": frequency,
            "dominant_reason": dominant_reason,
            "reason_breakdown": dict(g["reasons"]),
            "tools": sorted(g["tools"]),
            "priority": priority,
            "score": score,
            "sample_lines": g["lines"][:3],
        })

    candidates.sort(key=lambda c: (-c["score"], -c["frequency"]))

    # Greedy diversity: vong 1 - moi repo lay toi da 1 candidate (candidate diem cao
    # nhat cua repo do); vong 2 - neu chua du TOP_N, lay tiep candidate con lai theo
    # diem, khong gioi han repo nua.
    seen_repos = set()
    round1, round2 = [], []
    for c in candidates:
        if c["repo"] not in seen_repos:
            round1.append(c)
            seen_repos.add(c["repo"])
        else:
            round2.append(c)
    selected = (round1 + round2)[:TOP_N]

    n_distinct_repos_total = len({c["repo"] for c in candidates})
    n_distinct_repos_selected = len({c["repo"] for c in selected})

    out = {
        "summary": {
            "n_nonresolved_before_noise_filter": len(all_nonresolved),
            "n_excluded_test_repo_noise": n_noise_excluded,
            "n_unresolved_lines_considered": len(rows),
            "n_excluded_local_reference": sum(
                1 for r in data["rows"] if r["reason_category"] in EXCLUDED_REASONS
            ),
            "n_candidate_policies_total": len(candidates),
            "n_distinct_repos_total": n_distinct_repos_total,
            "top_n_selected": len(selected),
            "n_distinct_repos_in_selection": n_distinct_repos_selected,
            "reason_priority_weights": REASON_PRIORITY,
            "note": (
                "Da loai toan bo dong is_test_repo_noise=true (repo/workflow "
                "demo-poc-canary cua he sinh thai step-security) khoi ranking "
                "truoc khi chon top-N, khong chi ha uu tien - xem "
                "quantify_test_repo_noise.py."
            ),
        },
        "selected_probe_candidates": selected,
        "all_candidates_ranked": candidates,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 78)
    print(f"TOP {len(selected)} S3 PROBE CANDIDATES (trong {len(candidates)} policy co unresolved)")
    print(f"  Da dang: {n_distinct_repos_selected}/{len(selected)} candidate tu repo khac nhau")
    print("=" * 78)
    for i, c in enumerate(selected, 1):
        print(f"  {i:>2}. [{c['dominant_reason']:<26}] score={c['score']:<4} "
              f"freq={c['frequency']:<3} {c['repo']}")
        print(f"      {c['workflow']}#{c['job']}")
        print(f"      vd: {c['sample_lines'][0][:80]}")
    print(f"\n  Da ghi {OUT}")


if __name__ == "__main__":
    main()
