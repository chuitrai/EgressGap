#!/usr/bin/env python3
"""
build_d_static.py - Xay 3 phien ban D_static (S1-A / S1-B / S1-C) cho tung repo
trong corpus 609 repo cua Task B. CHUA tinh Precision/Recall/F1 o day - buoc do
lam RIENG sau (can quyet dinh cach xu ly domain TOOLING truoc khi so voi R_exec,
xem ghi chu trong static_rules.json ve rule 'harden_runner'). Script nay CHI
lam dung 1 viec: "code truoc" - dung du lieu/pipeline da co, ghep thanh 3 tap
domain du de so sanh, chua so sanh.

3 PHIEN BAN (dung ten S1-A/B/C theo thuat ngu da thong nhat voi Bao):
    S1-A (baseline)      = static_rules.json khop tren toan bo text workflow
    S1-B (+ AST tree)    = S1-A UNION parametric_targets.json RESOLVED
                           (Semgrep/Cosseter tren curl/wget/git-clone/helm)
    S1-C (+ data-flow)   = S1-B UNION parametric_dataflow_resolved.json
                           (intra-step VAR=literal, Phan 3, ~7 dong)

QUAN TRONG - TOOLING tach rieng: rule 'harden_runner' (ecosystem=tooling) khop
gan nhu MOI repo (bat ky repo nao dung Harden-Runner deu co dong 'uses:
step-security/harden-runner') nhung domain cua no (*.stepsecurity.io) la ha
tang cua CHINH cong cu enforcement, khong phai dependency workload - R_exec
(Task B, R_log v2) da loai domain nay ra roi (xem TOOLING_SUFFIX_RE trong
extract_rlog_v2.py). De 2 ben so sanh CUNG granularity, D_static cung PHAI tach
domain co ecosystem=='tooling' ra rieng, KHONG dua vao S1-A/B/C - neu khong, moi
repo dung Harden-Runner se bi tinh False Positive gia tao boi 1 domain khong
bao gio co the xuat hien trong R_exec (WORKLOAD-only) theo dinh nghia.

INPUT
    measurement/taskb_selected_repos.json   - danh sach 609 repo (corpus so sanh)
    measurement/static_rules.json           - S1-A
    measurement/parametric_targets.json     - S1-B (Bien 2)
    measurement/parametric_dataflow_resolved.json - S1-C (Bien 3, Phan 3)
    data/policies_ci.jsonl, data/files_ci.jsonl, data/files/*

OUTPUT
    measurement/d_static_versions.json
        { repo: {"A": [...], "B": [...], "C": [...], "tooling": [...],
                  "n_files_matched": int} }

CHAY
    uv run python measurement/build_d_static.py
"""
from teep import paths as _P
import json
import re
from pathlib import Path

DATA = _P.data("data")
RULES = json.loads(Path(str(_P.config("static_rules.json"))).read_text(encoding="utf-8"))["rules"]
for r in RULES:
    r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]

SELECTED = json.loads(Path(str(_P.data("measurement/taskb_selected_repos.json"))).read_text(encoding="utf-8"))["selected"]
SELECTED_REPOS = {c["repo"] for c in SELECTED}
print(f"[*] Corpus so sanh (Task B): {len(SELECTED_REPOS)} repo")


def load_eff_paths_by_repo():
    """Dung LAI dung filter cua taskb_select_repos.py (enforced, khong templating,
    co hosts) de tim TAT CA (repo, path) da gop thanh declared_hosts cua tung repo -
    vi declared_hosts la UNION nhieu file, khong phai 1 file duy nhat."""
    by_repo = {}
    with open(DATA / "policies_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["repo"] not in SELECTED_REPOS:
                continue
            ep = (r.get("egress_policy") or "").strip()
            enforced = r.get("enforced")
            if enforced is None:
                enforced = ep == "block"
            if not enforced or r.get("uses_templating") or not r.get("hosts"):
                continue
            by_repo.setdefault(r["repo"], set()).add(r["path"])
    return by_repo


def load_blob_index():
    idx = {}
    with open(DATA / "files_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            idx[(r["repo"], r["path"])] = r["blob"]
    return idx


def s1a_for_text(txt):
    """Tra ve (workload_domains:set, tooling_domains:set) cho 1 file text."""
    workload, tooling = set(), set()
    for r in RULES:
        if not any(rx.search(txt) for rx in r["_re"]):
            continue
        target = tooling if r.get("ecosystem") == "tooling" else workload
        for d in r["domains"]:
            target.add(d.lower())
    return workload, tooling


def main():
    eff_paths = load_eff_paths_by_repo()
    blob_idx = load_blob_index()

    # S1-B: gom domain RESOLVED tu parametric_targets.json theo repo (bo qua
    # is_test_repo_noise=True, dung ky luat loc nhieu da thong nhat tu Task A)
    parametric = json.loads(Path(str(_P.data("measurement/parametric_targets.json"))).read_text(encoding="utf-8"))
    b_by_repo = {}
    for row in parametric["rows"]:
        if row["resolution"] != "RESOLVED" or row["is_test_repo_noise"]:
            continue
        if row["repo"] not in SELECTED_REPOS:
            continue
        b_by_repo.setdefault(row["repo"], set()).add(row["resolved_domain"].lower())

    # S1-C: + domain Phan 3 (intra-step data-flow)
    dataflow_path = Path(str(_P.data("measurement/parametric_dataflow_resolved.json")))
    c_extra_by_repo = {}
    if dataflow_path.exists():
        dataflow = json.loads(dataflow_path.read_text(encoding="utf-8"))
        for row in dataflow["resolved_rows"]:
            if row["repo"] not in SELECTED_REPOS:
                continue
            c_extra_by_repo.setdefault(row["repo"], set()).add(row["resolved_domain"].lower())

    result = {}
    n_no_files = 0
    for repo in sorted(SELECTED_REPOS):
        paths = eff_paths.get(repo, set())
        workload, tooling = set(), set()
        n_matched_files = 0
        for path in paths:
            blob = blob_idx.get((repo, path))
            if not blob:
                continue
            try:
                txt = (DATA / "files" / blob).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            n_matched_files += 1
            w, t = s1a_for_text(txt)
            workload |= w
            tooling |= t
        if n_matched_files == 0:
            n_no_files += 1

        a = workload
        b = a | b_by_repo.get(repo, set())
        c = b | c_extra_by_repo.get(repo, set())

        result[repo] = {
            "A": sorted(a), "B": sorted(b), "C": sorted(c),
            "tooling": sorted(tooling),
            "n_files_matched": n_matched_files,
        }

    if n_no_files:
        print(f"[!] {n_no_files}/{len(SELECTED_REPOS)} repo khong doc duoc file workflow nao "
              f"(co the da doi ten/xoa sau khi crawl) - D_static rong cho cac repo nay.")

    Path(str(_P.data("measurement/d_static_versions.json"))).write_text(
        json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8"
    )

    # thong ke nhanh (chi de kiem tra sanity, KHONG phai Precision/Recall/F1)
    import statistics
    for v in ("A", "B", "C"):
        sizes = [len(result[r][v]) for r in result]
        print(f"  |S1-{v}|  median={statistics.median(sizes)}  mean={round(statistics.mean(sizes),2)}  "
              f"max={max(sizes)}  n_repo_with_any={sum(1 for s in sizes if s>0)}")
    tooling_sizes = [len(result[r]["tooling"]) for r in result]
    print(f"  |tooling| median={statistics.median(tooling_sizes)}  "
          f"n_repo_with_tooling={sum(1 for s in tooling_sizes if s>0)}")
    print("\n>>> measurement/d_static_versions.json")
    print("    (chua so sanh voi R_exec - buoc metric lam rieng, sau khi Bao xac nhan)")


if __name__ == "__main__":
    main()
