#!/usr/bin/env python3
"""
resolve_intrastep_dataflow.py - Phan 3 (S1-C): lightweight intra-step data-flow.

PHAM VI (co tinh, khong mo rong): CHI resolve bien duoc gan LITERAL (VAR=https://...)
o MOT dong TRUOC do TRONG CUNG 1 step. Khong theo bien qua nhieu step, khong resolve
command substitution ($(...)), khong resolve secrets/context GHA ($GITHUB_*, ${{ }}).
Day la ranh gioi da thong nhat voi Bao - vuot qua ranh gioi nay la full program
analysis, khong con la "lightweight".

CAN CU: check_dataflow_roi.py (script kiem tra rieng, chua sua code chinh) da xac
nhan bang du lieu that: trong 26 dong roi vao reason_category=dynamic_variable_expression
(tu parametric_targets.json), chi 7/26 (27%) co the resolve theo cach nay - phan con
lai la $(...) command substitution, bien tu step/job khac, hoac GHA context/secrets,
DUNG loai ma lightweight intra-step PHAI bo qua (khong doan). Script nay hien thuc hoa
dung 7 truong hop do thanh code chinh thuc, khong con la ban kiem tra rieng.

INPUT   measurement/parametric_targets.json (rows co reason_category ==
        "dynamic_variable_expression")
        data/files_ci.jsonl, data/files/*  (doc lai step["run"] goc)
OUTPUT  measurement/parametric_dataflow_resolved.json
        - moi phan tu: 1 row nhu trong parametric_targets.json, THEM
          "resolution_method": "intra_step_var_literal", "resolution": "RESOLVED",
          "resolved_domain": <domain>, cac row KHONG resolve duoc van giu nguyen
          UNRESOLVED, KHONG doan.

CHAY
    uv run python measurement/resolve_intrastep_dataflow.py
"""
from teep import paths as _P
import json
import re
import sys
from pathlib import Path

pass  # sys.path hack removed: package imports via teep.*
                                                        # extract_parametric_targets.py o measurement/ (len 1 cap)
from teep.static.extract_parametric_targets import classify_target  # noqa: E402  (tai dung dung 1 ham chuan)

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = _P.data("data")
TARGETS = Path(str(_P.data("measurement/parametric_targets.json")))
OUT = Path(str(_P.data("measurement/parametric_dataflow_resolved.json")))

VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
# Chi chap nhan gan LITERAL ro rang: VAR=gia_tri (khong co $, khong co $(...), khong
# co ${{ }} o VE PHAI - neu co thi ban than gia tri gan cung la dynamic, khong phai
# "literal" thuc su, phai bo qua (UNRESOLVED), khong duoc coi la resolve duoc.
VAR_LITERAL_ASSIGN_TMPL = r'^\s*{name}=["\']?([^\s"\'$]+)'

# Phat hien qua chay that (khong doan truoc): classify_target() resolve duoc
# "http://localhost:7860" thanh host="localhost" ve mat cu phap - dung, nhung day
# KHONG phai domain egress that (khong bao gio xuat hien trong bat ky allowlist
# nao, khong co y nghia trong bai toan nay). Loai rieng, ghi ro ly do thay vi am
# tham bo qua.
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def load_file_index():
    idx = {}
    with open(DATA / "files_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            idx[(r["repo"], r["path"])] = r["blob"]
    return idx


def get_step_run_lines(file_idx, yaml_cache, repo, workflow, job, step_index):
    import yaml
    key = (repo, workflow)
    blob = file_idx.get(key)
    if not blob:
        return None
    if blob not in yaml_cache:
        try:
            yaml_cache[blob] = yaml.safe_load(
                (DATA / "files" / blob).read_text(encoding="utf-8", errors="replace")
            )
        except Exception:
            yaml_cache[blob] = None
    content = yaml_cache[blob]
    if not isinstance(content, dict):
        return None
    job_body = (content.get("jobs") or {}).get(job)
    if not isinstance(job_body, dict):
        return None
    steps = job_body.get("steps") or []
    if step_index >= len(steps):
        return None
    step = steps[step_index]
    run_text = step.get("run", "") if isinstance(step, dict) else ""
    if not isinstance(run_text, str):
        return None
    return run_text.splitlines()


def try_resolve(row, file_idx, yaml_cache):
    """Tra ve (resolved_domain, literal_value) hoac (None, None) neu khong resolve duoc
    theo dung ranh gioi da thong nhat (literal, cung step, dong gan TRUOC dong dung)."""
    m = VAR_REF_RE.search(row["raw_line"])
    if not m:
        return None, None
    varname = m.group(1)
    lines = get_step_run_lines(file_idx, yaml_cache, row["repo"], row["workflow"],
                                row["job"], row["step_index"])
    if lines is None:
        return None, None

    assign_re = re.compile(VAR_LITERAL_ASSIGN_TMPL.format(name=re.escape(varname)))
    usage_line_idx = row.get("line_index")
    literal = None
    for i, l in enumerate(lines):
        # neu biet vi tri dong dung (line_index tu parametric_locate.py), chi nhan
        # gan XUAT HIEN TRUOC dong do trong CUNG step - dung huong data-flow that,
        # khong nhan gan lai o sau (se sai chieu nhan qua).
        if usage_line_idx is not None and i > usage_line_idx:
            break
        am = assign_re.match(l)
        if am:
            literal = am.group(1)
    if literal is None:
        return None, None
    resolution, domain, reason = classify_target(literal)
    if resolution == "RESOLVED" and domain not in LOCALHOST_NAMES:
        return domain, literal
    return None, None


def main():
    data = json.loads(TARGETS.read_text(encoding="utf-8"))
    rows = [r for r in data["rows"] if r["reason_category"] == "dynamic_variable_expression"]
    print(f"[*] {len(rows)} dong dynamic_variable_expression can thu resolve (intra-step, literal-only)")

    file_idx = load_file_index()
    yaml_cache = {}

    resolved_rows = []
    still_unresolved = 0
    for row in rows:
        domain, literal = try_resolve(row, file_idx, yaml_cache)
        if domain:
            new_row = dict(row)
            new_row["resolution"] = "RESOLVED"
            new_row["resolved_domain"] = domain
            new_row["resolution_reason"] = "intra_step_var_literal"
            new_row["reason_category"] = None
            new_row["resolution_method"] = "intra_step_var_literal"
            new_row["literal_assignment_value"] = literal
            resolved_rows.append(new_row)
        else:
            still_unresolved += 1

    print(f"[*] RESOLVED moi (Phan 3): {len(resolved_rows)}")
    print(f"[*] Van UNRESOLVED (dung ranh gioi, khong doan): {still_unresolved}")
    if resolved_rows:
        print("\n--- chi tiet cac dong RESOLVED moi ---")
        for r in resolved_rows:
            print(f"  {r['repo']:45s} {r['resolved_domain']:35s} (tu '{r['literal_assignment_value'][:50]}')")

    OUT.write_text(json.dumps({
        "n_input_dynamic_variable_expression": len(rows),
        "n_resolved": len(resolved_rows),
        "n_still_unresolved": still_unresolved,
        "note": (
            "Chi resolve VAR=literal CUNG step, xuat hien TRUOC dong dung (huong "
            "data-flow dung). Khong theo bien qua step khac, khong resolve $(...) "
            "hay context/secrets GHA - dung ranh gioi 'lightweight intra-step' da "
            "thong nhat. Ty le du kien ~27% (7/26) theo check_dataflow_roi.py; sau "
            "khi loai 1 case localhost (khong phai domain egress that) con 6/26."
        ),
        "resolved_rows": resolved_rows,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> {OUT}")


if __name__ == "__main__":
    main()
