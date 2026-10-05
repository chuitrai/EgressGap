#!/usr/bin/env python3
"""
extract_step_patterns.py - TASK A (Phan 3 ke hoach): trich step pattern tu corpus.

v2 - bo sung theo 6 diem review:
  1. provenance (repo/workflow/job/policy) giu lai cho tung occurrence, aggregate ra
     n_policies / n_workflows / n_repositories (khong chi dem "count" tho).
  2. phan biet 3 loai KHONG nhan dien duoc: LOCAL_FILE (biet phai parse tiep sau nay),
     UNKNOWN_COMMAND (chua co rule), PARSE_ERROR (YAML khong doc duoc).
  3. tach block "run:" nhieu dong thanh tung DONG truoc khi regex-match (line-level),
     thay vi match ca khoi text.
  4. moi pattern co category + ecosystem (PACKAGE_DOWNLOAD/CONTAINER_PULL/...).
  5. cumulative coverage la SET-UNION that su: |union W(p_1..p_k)| / |W|, khong phai
     tong % tung pattern (tong se vuot 100% vi 1 policy chua nhieu pattern).
  6. xuat rieng muc "unrecognized" (policy hoan toan khong co pattern nao) de tra loi
     truc tiep cau hoi 2 cua Phan 3 va lam ro gioi han cua static extractor.

DINH NGHIA DON VI (quan trong, tranh nham 6.190 vs 1.212):
    policy = 1 JOB trong 1 workflow co harden-runner enforced (1 dong trong
             data/policies_ci.jsonl sau loc). Corpus co 6.190 policy.
    repo   = 1 git repository. Cung corpus do co 1.212 repo PHAN BIET
             (trung binh ~5.1 policy/repo - vi 1 repo thuong co nhieu workflow,
             1 workflow co nhieu job). 6.190 va 1.212 la HAI DON VI DEM khac nhau
             tren CUNG MOT tap du lieu (khong phai "raw truoc dedup" vs "final sau
             dedup") - script in ro dong nay trong summary de khoi nham trong paper.

CHAY
    uv run python measurement/extract_step_patterns.py
"""
from teep import paths as _P
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

POLICIES = Path(str(_P.data("data/policies_ci.jsonl")))
FILES_INDEX = Path(str(_P.data("data/files_ci.jsonl")))
FILES_DIR = Path(str(_P.data("data/files")))
OUT = Path(str(_P.data("measurement/step_patterns.json")))

# --- (4) Rule nhan dien pattern tu 1 DONG lenh trong "run:", co category/ecosystem ---
CMD_RULES = [
    dict(name="npm ci",          rx=r"\bnpm\s+ci\b",                     category="PACKAGE_DOWNLOAD", ecosystem="npm"),
    dict(name="npm install",     rx=r"\bnpm\s+(install|i)\b",            category="PACKAGE_DOWNLOAD", ecosystem="npm"),
    dict(name="yarn",            rx=r"\byarn\b",                         category="PACKAGE_DOWNLOAD", ecosystem="npm"),
    dict(name="pnpm install",    rx=r"\bpnpm\s+(install|i)\b",           category="PACKAGE_DOWNLOAD", ecosystem="npm"),
    dict(name="pip install",     rx=r"\bpip[3]?\s+install\b",            category="PACKAGE_DOWNLOAD", ecosystem="pypi"),
    dict(name="pip download",    rx=r"\bpip[3]?\s+download\b",           category="PACKAGE_DOWNLOAD", ecosystem="pypi"),
    dict(name="poetry",          rx=r"\bpoetry\s+(install|update|lock)\b", category="PACKAGE_DOWNLOAD", ecosystem="pypi"),
    dict(name="cargo build",     rx=r"\bcargo\s+(build|test)\b",         category="PACKAGE_DOWNLOAD", ecosystem="cargo"),
    dict(name="cargo fetch",     rx=r"\bcargo\s+fetch\b",                category="PACKAGE_DOWNLOAD", ecosystem="cargo"),
    dict(name="go build/test",   rx=r"\bgo\s+(build|test|vet)\b",        category="PACKAGE_DOWNLOAD", ecosystem="go"),
    dict(name="go mod download", rx=r"\bgo\s+mod\s+download\b",          category="PACKAGE_DOWNLOAD", ecosystem="go"),
    dict(name="go get",          rx=r"\bgo\s+get\b",                     category="PACKAGE_DOWNLOAD", ecosystem="go"),
    dict(name="docker pull",     rx=r"\bdocker\s+pull\b",                category="CONTAINER_PULL",   ecosystem="docker"),
    dict(name="docker build",    rx=r"\bdocker\s+build\b",               category="CONTAINER_PULL",   ecosystem="docker"),
    dict(name="apt-get",         rx=r"\bapt(-get)?\s+(install|update|upgrade)\b", category="SYSTEM_PACKAGE", ecosystem="debian"),
    dict(name="gem install",     rx=r"\bgem\s+install\b",                category="PACKAGE_DOWNLOAD", ecosystem="rubygems"),
    dict(name="bundle install",  rx=r"\bbundle\s+(install|exec)\b",      category="PACKAGE_DOWNLOAD", ecosystem="rubygems"),
    dict(name="mvn",             rx=r"\bmvn\s",                          category="PACKAGE_DOWNLOAD", ecosystem="maven"),
    dict(name="gradle",          rx=r"\bgradle(w)?\s",                   category="PACKAGE_DOWNLOAD", ecosystem="maven"),
    dict(name="curl",            rx=r"\bcurl\s",                        category="HTTP_REQUEST",     ecosystem="generic"),
    dict(name="wget",            rx=r"\bwget\s",                        category="HTTP_REQUEST",     ecosystem="generic"),
    dict(name="git clone",       rx=r"\bgit\s+clone\b",                  category="SOURCE_FETCH",     ecosystem="git"),
    # gh CLI luon noi chuyen voi api.github.com bat ke subcommand nao (issue/pr/
    # workflow/auth/secret/label/...) -> khop rong, khong gioi han 4 subcommand nhu ban dau.
    dict(name="gh cli",          rx=r"\bgh\s+\w",                        category="VCS_API",          ecosystem="github"),
    dict(name="terraform",       rx=r"\bterraform\s+(init|plan|apply)\b", category="IAC",              ecosystem="terraform"),
    dict(name="helm",            rx=r"\bhelm\s+(install|pull|repo)\b",   category="IAC",              ecosystem="helm"),
    dict(name="make",            rx=r"^\s*make\b",                      category="BUILD_TOOL",       ecosystem="generic"),
    dict(name="nuget/dotnet",    rx=r"\bdotnet\s+(restore|build|publish)\b", category="PACKAGE_DOWNLOAD", ecosystem="nuget"),
]
for r in CMD_RULES:
    r["compiled"] = re.compile(r["rx"])

ACTION_VERSION_RE = re.compile(r"@.*$")
IGNORE_ACTIONS = {"step-security/harden-runner"}

# (3) dong shell KHONG can phan loai: khong co ham y egress, hoac la control-flow.
# Muc dich: tranh bien UNKNOWN_COMMAND thanh "rac" tu nhung dong nhu `cd`, `echo`,
# `export FOO=bar`. Day la line-level, KHONG phai shell AST day du (co chu dinh,
# xem ghi chu diem 3 trong file huong dan).
NOOP_FIRST_TOKENS = {
    "cd", "echo", "export", "set", "mkdir", "rm", "cp", "mv", "source", ".",
    "exit", "cat", "ls", "pwd", "chmod", "chown", "touch", "true", "false",
    "sleep", "printf", "read", "shift", "return", "unset", "test", "[",
    "tar", "unzip", "gzip", "gunzip", "sed", "awk", "grep", "find", "which",
    "env", "shopt", "trap", "wait", "kill", "jobs", "cd..",
}
CONTROL_FLOW_TOKENS = {
    "if", "then", "else", "elif", "fi", "do", "done", "case", "esac",
    "while", "until", "for", "function", "{", "}", "EOF",
}
VAR_ASSIGN_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=\S*\s*$")
LOCAL_FILE_RE = re.compile(
    r"^(?:\./|\.\./|/)?[\w./-]*\b(?:bash|sh|zsh|python[3]?|ruby|perl|node|pwsh)\s+"
    r"(?P<script>[\w./-]+\.(?:sh|py|rb|pl|ps1|js|mjs))"
    r"|^(?P<direct>(?:\./|\.\./)[\w./-]+)"
)


def classify_line(line):
    """Tra ve (kind, value) voi kind in {PATTERN, LOCAL_FILE, UNKNOWN_COMMAND, None}.
    None = dong bi bo qua (comment / var-assign / control-flow-thuan-tuy / noop /
    flag tiep dien tu dong truoc co `\\`)."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or VAR_ASSIGN_RE.match(stripped):
        return None, None

    # (uu tien 1) CMD_RULES duoc thu TRUOC, ke ca tren dong co keyword dieu khien
    # o dau (vd "if curl -sf url; then" van phai bat duoc curl).
    for rule in CMD_RULES:
        if rule["compiled"].search(stripped):
            return "PATTERN", "run:" + rule["name"]

    m = LOCAL_FILE_RE.match(stripped)
    if m:
        path = m.group("script") or m.group("direct")
        return "LOCAL_FILE", path

    first_tok = stripped.split()[0] if stripped.split() else ""
    first_tok = first_tok.strip("|&;()").rstrip(";")

    if first_tok in NOOP_FIRST_TOKENS or first_tok in CONTROL_FLOW_TOKENS:
        return None, None
    if first_tok.startswith("-"):
        # dong tiep dien cua lenh nhieu dong voi `\` (vd `gh issue edit \` roi
        # `  --add-label x`) - flag khong bao gio la lenh doc lap, bo qua thay vi
        # bao UNKNOWN_COMMAND gia.
        return None, None
    if not first_tok or not re.match(r"^[\w./-]+$", first_tok):
        return None, None  # dong ky la (pipe phuc tap, heredoc...) - bo qua, khong ep phan loai

    return "UNKNOWN_COMMAND", first_tok


def normalize_action(uses):
    uses = uses.strip()
    if uses.startswith("docker://"):
        return "uses:docker://" + uses[len("docker://"):].split(":")[0]
    return "uses:" + ACTION_VERSION_RE.sub("", uses)


# category/ecosystem cho uses:, muon mo rong -> lay tu static_rules.json (khong bat
# buoc dung khi chay Task A doc lap, nhung neu co file thi cross-reference cho dep).
def load_action_ecosystem_hints():
    hints = {}
    path = Path(str(_P.config("static_rules.json")))
    if not path.exists():
        return hints
    try:
        rules = json.loads(path.read_text(encoding="utf-8"))["rules"]
    except Exception:
        return hints
    for r in rules:
        for pat in r.get("patterns", []):
            m = re.search(r"uses:\\?s\*(\S+)", pat)
            if m:
                hints[m.group(1).strip("\\")] = r.get("ecosystem", "unknown")
    return hints


def classify_step(step, ecosystem_hints):
    """Tra ve list (kind, pattern_or_value, category, ecosystem) cho 1 step."""
    out = []
    if not isinstance(step, dict):
        return out

    if isinstance(step.get("uses"), str):
        norm = normalize_action(step["uses"])
        action_name = norm[len("uses:"):]
        if action_name not in IGNORE_ACTIONS:
            eco = ecosystem_hints.get(action_name, "unknown")
            out.append(("PATTERN", norm, "ACTION", eco))

    if isinstance(step.get("run"), str):
        # (3) tach tung dong truoc khi phan loai, thay vi match ca khoi
        for raw_line in step["run"].splitlines():
            kind, val = classify_line(raw_line)
            if kind is None:
                continue
            if kind == "PATTERN":
                rule = next(r for r in CMD_RULES if "run:" + r["name"] == val)
                out.append(("PATTERN", val, rule["category"], rule["ecosystem"]))
            elif kind == "LOCAL_FILE":
                out.append(("LOCAL_FILE", val, None, None))
            elif kind == "UNKNOWN_COMMAND":
                out.append(("UNKNOWN_COMMAND", val, None, None))
    return out


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
    """Loc GIONG HET duplication_report.json de con so nhat quan xuyen suot deck."""
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


def main():
    policies = load_policies()
    file_idx = load_file_index()
    ecosystem_hints = load_action_ecosystem_hints()

    total = len(policies)
    all_repos = {p["repo"] for p in policies}

    # (1) provenance: pattern -> {policies:set[idx], workflows:set[(repo,path)], repos:set}
    pat_policies = defaultdict(set)
    pat_workflows = defaultdict(set)
    pat_repos = defaultdict(set)
    pat_meta = {}  # pattern -> (category, ecosystem)

    policies_with_pattern = 0
    policies_via_job_fallback = 0
    unrecognized = []  # (6) danh sach policy KHONG co pattern nao

    yaml_cache = {}
    missing_file = 0
    yaml_errors = 0

    for policy_idx, p in enumerate(policies):
        key = (p["repo"], p["path"])
        blob = file_idx.get(key)
        if blob is None:
            missing_file += 1
            unrecognized.append({
                "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                "type": "PARSE_ERROR", "detail": "khong tim thay file goc trong files_ci.jsonl",
            })
            continue

        if blob not in yaml_cache:
            fpath = FILES_DIR / blob
            try:
                yaml_cache[blob] = yaml.safe_load(
                    fpath.read_text(encoding="utf-8", errors="replace")
                )
            except Exception as e:
                yaml_cache[blob] = ("__ERROR__", str(e))
        content = yaml_cache[blob]

        if isinstance(content, tuple) and content[0] == "__ERROR__":
            yaml_errors += 1
            unrecognized.append({
                "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                "type": "PARSE_ERROR", "detail": content[1][:200],
            })
            continue
        if not isinstance(content, dict):
            yaml_errors += 1
            unrecognized.append({
                "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                "type": "PARSE_ERROR", "detail": "YAML khong parse ra dict",
            })
            continue

        jobs = content.get("jobs") or {}
        job_body = jobs.get(p["job"]) if isinstance(jobs, dict) else None
        via_fallback = False

        # Job-level "uses:" = goi reusable workflow, khong co "steps:" o cap nay
        # (dung phap GH Actions loai tru lan nhau giua uses/steps o cap job).
        # Truoc day bi rot vao "job khong co step run/uses" mot cach oan uong.
        if isinstance(job_body, dict) and isinstance(job_body.get("uses"), str):
            ref = ACTION_VERSION_RE.sub("", job_body["uses"].strip())
            found_patterns = {("job-uses:" + ref, "ACTION", "reusable-workflow")}
            policies_with_pattern += 1
            for pat, category, ecosystem in found_patterns:
                pat_policies[pat].add(policy_idx)
                pat_workflows[pat].add(key)
                pat_repos[pat].add(p["repo"])
                pat_meta[pat] = (category, ecosystem)
            continue

        if isinstance(job_body, dict):
            steps = job_body.get("steps") or []
        else:
            via_fallback = True
            steps = []
            if isinstance(jobs, dict):
                for jb in jobs.values():
                    if isinstance(jb, dict):
                        steps.extend(jb.get("steps") or [])

        found_patterns = set()
        local_unrecognized = []  # (6) chi giu lai neu policy nay CUOI CUNG khong co pattern nao
        for step in steps:
            for kind, val, category, ecosystem in classify_step(step, ecosystem_hints):
                if kind == "PATTERN":
                    found_patterns.add((val, category, ecosystem))
                else:
                    local_unrecognized.append({
                        "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                        "type": kind, "detail": val,
                    })

        if found_patterns:
            policies_with_pattern += 1
            if via_fallback:
                policies_via_job_fallback += 1
            for pat, category, ecosystem in found_patterns:
                pat_policies[pat].add(policy_idx)
                pat_workflows[pat].add(key)
                pat_repos[pat].add(p["repo"])
                pat_meta[pat] = (category, ecosystem)
        else:
            if local_unrecognized:
                unrecognized.extend(local_unrecognized)
            else:
                unrecognized.append({
                    "repo": p["repo"], "workflow": p["path"], "job": p["job"],
                    "type": "UNKNOWN_COMMAND", "detail": "job khong co step run/uses nao doc duoc",
                })

    policies_without_pattern = total - policies_with_pattern

    # (5) cumulative coverage = SET-UNION that su, khong phai tong tung %
    rows = []
    covered_policies = set()
    for pat, _ in Counter({k: len(v) for k, v in pat_policies.items()}).most_common():
        covered_policies |= pat_policies[pat]
        category, ecosystem = pat_meta[pat]
        rows.append({
            "pattern": pat,
            "category": category,
            "ecosystem": ecosystem,
            "n_policies": len(pat_policies[pat]),
            "n_workflows": len(pat_workflows[pat]),
            "n_repositories": len(pat_repos[pat]),
            "pct_of_total_policies": round(100 * len(pat_policies[pat]) / total, 2) if total else 0,
            "cumulative_coverage_pct": round(100 * len(covered_policies) / total, 2) if total else 0,
        })

    out = {
        "summary": {
            "note_units": (
                "policy = 1 job (1 dong trong data/policies_ci.jsonl sau loc "
                "enforced=true/khong template/co host). repo = 1 git repository. "
                "6190 policy va 1212 repo la HAI DON VI DEM tren CUNG MOT corpus "
                "(khong phai raw-vs-final); trung binh moi repo co ~5.1 policy."
            ),
            "n_policies": total,
            "n_repositories": len(all_repos),
            "n_policies_with_pattern": policies_with_pattern,
            "n_policies_without_pattern": policies_without_pattern,
            "n_policies_pattern_only_via_job_name_fallback": policies_via_job_fallback,
            "missing_source_file": missing_file,
            "yaml_parse_errors": yaml_errors,
            "n_distinct_patterns": len(rows),
            "unrecognized_findings_count": len(unrecognized),
        },
        "patterns": rows,
        "unrecognized": unrecognized,
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- in bao cao ngan gon ---
    s = out["summary"]
    print("=" * 82)
    print(f"TASK A v2: {s['n_policies']} policy / {s['n_repositories']} repo")
    print("=" * 82)
    print(f"  co >=1 pattern nhan dien duoc         : {s['n_policies_with_pattern']} "
          f"({100*s['n_policies_with_pattern']/total:.1f}%)")
    print(f"  KHONG co pattern nao (cau hoi 2)       : {s['n_policies_without_pattern']} "
          f"({100*s['n_policies_without_pattern']/total:.1f}%)")
    print(f"  trong do nho job-name fallback (~noisy): {s['n_policies_pattern_only_via_job_name_fallback']}")
    print(f"  thieu file goc / loi parse YAML        : {s['missing_source_file'] + s['yaml_parse_errors']}")
    print(f"  so pattern phan biet                   : {s['n_distinct_patterns']}")
    print()
    print(f"{'pattern':<32}{'category':<18}{'n_pol':>7}{'n_wf':>7}{'n_repo':>8}{'cum %':>9}")
    for row in rows[:30]:
        print(f"{row['pattern']:<32}{row['category']:<18}{row['n_policies']:>7}"
              f"{row['n_workflows']:>7}{row['n_repositories']:>8}{row['cumulative_coverage_pct']:>9.1f}")
    print()

    n90 = next((i + 1 for i, r in enumerate(rows) if r["cumulative_coverage_pct"] >= 90), None)
    if n90:
        print(f"  -> top {n90} pattern (theo tan suat) da cham >=90% policy (cau hoi 1)")
    else:
        print("  -> khong dat 90% union coverage voi cac rule hien co")

    from collections import Counter as _C
    type_counts = _C(u["type"] for u in unrecognized)
    print()
    print("  --- unrecognized breakdown (cau hoi 2/3) ---")
    for t, n in type_counts.most_common():
        print(f"    {t:<18}{n}")


if __name__ == "__main__":
    main()
