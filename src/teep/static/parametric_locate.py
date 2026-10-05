#!/usr/bin/env python3
"""
parametric_locate.py - Buoc 1 cua giai doan "Cosseter-style extraction".

MUC DICH
    Task A (extract_step_patterns.py) da xac dinh 5 pattern PARAMETRIC:
    run:curl, run:wget, run:git clone, run:gh cli, run:helm (666 luot policy).
    Truoc khi chay Semgrep, can:
      (a) Dinh vi CHINH XAC tung dong lenh (repo/workflow/job/step_idx/line) de
          sau nay ghep ket qua Semgrep nguoc lai dung cho vao pattern_locations.
      (b) Do ty le shell: bao nhieu % thuc su la bash/sh (Cosseter chi ho tro
          `languages: [bash]`) - quyet dinh scope bash-only co hop ly khong
          (nguong thoa thuan: >90% -> bash-only, con lai ghi limitation).

CACH RESOLVE SHELL (uu tien giam dan, dung dung thu tu GitHub Actions):
    1. step["shell"]                                   (khai bao rieng cho step)
    2. job["defaults"]["run"]["shell"]                 (mac dinh cap job)
    3. workflow["defaults"]["run"]["shell"]             (mac dinh cap workflow)
    4. suy tu job["runs-on"]: windows-* -> pwsh, con lai (ubuntu-*/macos-*/self-hosted
       khong ro) -> bash (dung mac dinh GitHub-hosted runner)

CHAY
    uv run python measurement/parametric_locate.py
"""
from teep import paths as _P
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

POLICIES = Path(str(_P.data("data/policies_ci.jsonl")))
FILES_INDEX = Path(str(_P.data("data/files_ci.jsonl")))
FILES_DIR = Path(str(_P.data("data/files")))
OUT = Path(str(_P.data("measurement/parametric_locations.json")))

# Chi 4 tool THUC SU can Semgrep (xem ghi chu ve gh cli o cuoi file: domain cua no
# co dinh la api.github.com bat ke subcommand, nen KHONG dua vao day - xu ly rieng
# nhu mot static_rules.json entry moi, khong can trich argument).
PARAMETRIC_RULES = [
    dict(name="curl",      rx=re.compile(r"\bcurl\s")),
    dict(name="wget",      rx=re.compile(r"\bwget\s")),
    dict(name="git clone", rx=re.compile(r"\bgit\s+clone\b")),
    dict(name="helm",      rx=re.compile(r"\bhelm\s+(install|pull|repo)\b")),
]
# gh cli van duoc DINH VI (de kiem tra gia dinh "domain co dinh"), nhung se KHONG
# dua vao Semgrep - xem PHAN KIEM TRA GH_HOST o cuoi.
GH_CLI_RX = re.compile(r"\bgh\s+\w")

CONTROL_FLOW_TOKENS = {
    "if", "then", "else", "elif", "fi", "do", "done", "case", "esac",
    "while", "until", "for", "function", "{", "}", "EOF",
}
VAR_ASSIGN_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=\S*\s*$")


def load_file_index():
    idx = {}
    with FILES_INDEX.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            idx[(r["repo"], r["path"])] = r["blob"]
    return idx


def load_policies():
    out = []
    with POLICIES.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            if not (r.get("endpoints") or r.get("hosts")):
                continue
            out.append(r)
    return out


def resolve_shell(step, job_body, content):
    if isinstance(step.get("shell"), str):
        return step["shell"], "step"
    for scope, obj in (("job", job_body), ("workflow", content)):
        try:
            sh = obj.get("defaults", {}).get("run", {}).get("shell")
        except AttributeError:
            sh = None
        if isinstance(sh, str):
            return sh, scope
    runs_on = job_body.get("runs-on") if isinstance(job_body, dict) else None
    runs_on_str = json.dumps(runs_on).lower() if runs_on else ""
    if "windows" in runs_on_str:
        return "pwsh", "runs-on-default(windows)"
    return "bash", "runs-on-default(non-windows)"


def shell_family(shell_str):
    s = (shell_str or "").lower()
    if s in ("bash", "sh") or s.startswith("bash ") or s.startswith("sh "):
        return "bash/sh"
    if "pwsh" in s or "powershell" in s:
        return "pwsh"
    if s == "cmd":
        return "cmd"
    if "python" in s:
        return "python"
    return f"other({s})"


def main():
    policies = load_policies()
    file_idx = load_file_index()
    yaml_cache = {}

    locations = []       # cac dong PARAMETRIC (4 tool can Semgrep)
    gh_cli_locations = []  # rieng gh cli, de kiem tra gia dinh domain co dinh
    shell_counter = Counter()

    for policy_idx, p in enumerate(policies):
        key = (p["repo"], p["path"])
        blob = file_idx.get(key)
        if blob is None:
            continue
        if blob not in yaml_cache:
            try:
                yaml_cache[blob] = yaml.safe_load(
                    (FILES_DIR / blob).read_text(encoding="utf-8", errors="replace")
                )
            except Exception:
                yaml_cache[blob] = None
        content = yaml_cache[blob]
        if not isinstance(content, dict):
            continue

        jobs = content.get("jobs") or {}
        job_body = jobs.get(p["job"]) if isinstance(jobs, dict) else None
        if not isinstance(job_body, dict):
            continue
        steps = job_body.get("steps") or []

        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            shell_str, shell_scope = resolve_shell(step, job_body, content)
            fam = shell_family(shell_str)

            for line_idx, raw_line in enumerate(step["run"].splitlines()):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#") or VAR_ASSIGN_RE.match(stripped):
                    continue
                first_tok = stripped.split()[0].strip("|&;()").rstrip(";") if stripped.split() else ""
                if first_tok in CONTROL_FLOW_TOKENS:
                    continue

                matched_tool = None
                for rule in PARAMETRIC_RULES:
                    if rule["rx"].search(stripped):
                        matched_tool = rule["name"]
                        break

                if matched_tool:
                    shell_counter[fam] += 1
                    locations.append({
                        "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                        "step_index": step_idx, "line_index": line_idx,
                        "tool": matched_tool, "shell": shell_str, "shell_family": fam,
                        "shell_scope": shell_scope, "raw_line": stripped,
                    })
                elif GH_CLI_RX.search(stripped):
                    gh_cli_locations.append({
                        "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                        "step_index": step_idx, "line_index": line_idx,
                        "raw_line": stripped,
                    })

    total = len(locations)
    fam_counts = Counter(loc["shell_family"] for loc in locations)

    print("=" * 78)
    print(f"Dinh vi 4 tool PARAMETRIC can Semgrep: {total} dong lenh")
    print("=" * 78)
    for fam, n in fam_counts.most_common():
        print(f"  {fam:<20}{n:>6}   ({100*n/total:.1f}%)" if total else "")
    bash_pct = 100 * fam_counts.get("bash/sh", 0) / total if total else 0
    print()
    if bash_pct >= 90:
        print(f"  -> {bash_pct:.1f}% la bash/sh (>=90%) => SCOPE bash-only, "
              f"{total - fam_counts.get('bash/sh', 0)} dong non-bash ghi limitation.")
    else:
        print(f"  -> chi {bash_pct:.1f}% la bash/sh (<90%) => can xem lai scope, "
              f"khong the coi bash-only la du dai dien.")

    print()
    print("--- kiem tra gia dinh 'gh cli domain co dinh' ---")
    print(f"  tong dong 'gh <subcommand>' (tach rieng, khong dua vao Semgrep): {len(gh_cli_locations)}")
    override_rx = re.compile(r"GH_HOST|GITHUB_API_URL|GH_ENTERPRISE")
    overrides = [loc for loc in gh_cli_locations if override_rx.search(loc["raw_line"])]
    print(f"  so dong co override GH_HOST/GITHUB_API_URL/GH_ENTERPRISE: {len(overrides)}")
    if overrides:
        for o in overrides[:5]:
            print(f"    {o['repo']}:{o['workflow']}#{o['job']}  {o['raw_line'][:80]}")
    else:
        print("  -> khong thay override nao trong text tinh -> gia dinh domain co dinh "
              "(api.github.com, + uploads.github.com cho release upload) la hop ly.")

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({
        "summary": {
            "total_parametric_lines": total,
            "shell_family_breakdown": dict(fam_counts),
            "bash_pct": round(bash_pct, 2),
            "bash_only_scope_justified": bash_pct >= 90,
            "gh_cli_total_lines": len(gh_cli_locations),
            "gh_cli_host_override_detected": len(overrides),
        },
        "locations": locations,
        "gh_cli_locations": gh_cli_locations,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Da ghi {OUT}")


if __name__ == "__main__":
    main()
