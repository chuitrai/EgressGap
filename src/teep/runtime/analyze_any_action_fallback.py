#!/usr/bin/env python3
"""
Phase 1 (S1-A baseline mo rong): tinh tan suat that cua tung `uses: action` dang
roi vao fallback `any_action` (confidence=low) trong static_rules.json, de biet
nen uu tien them rule rieng cho action nao truoc - thay vi doan.

Dinh nghia "roi vao fallback": ten action (vd. "actions/checkout", da bo phan
@version) trich tu dong `uses:` trong workflow text, KHONG khop truc tiep bat ky
pattern nao cua CAC RULE KHAC any_action trong static_rules.json (ke ca cac
rule ecosystem pip/npm/go/... vi ban than chung cung co pattern "uses: actions/
setup-X" - da phat hien va sua 1 lan loi bo sot dieu nay truoc khi chay ban
chinh thuc, xem ghi chu duoi day).

Dung DUNG corpus ma validate_static_rules.py da dung (policies_ci.jsonl, loc
enforced + khong templating + co hosts) de nhat quan voi cach S1 da duoc hieu
chuan - khong gioi han vao 609 repo cua Task B (Task B la mau doc lap de kiem
R_log, khong phai corpus hieu chuan S1).
"""
from teep import paths as _P
import json
import re
from collections import Counter
from pathlib import Path

DATA = _P.data("data")
RULES = json.loads(Path(str(_P.config("static_rules.json"))).read_text(encoding="utf-8"))["rules"]

# MOI rule TRU any_action deu duoc coi la "da co rule rieng" - ke ca cac rule
# ecosystem (pip/npm/go/cargo/gradle/rubygems/...) VI ban than chung cung co
# pattern "uses: actions/setup-X" (vd. pip co "uses:\s*actions/setup-python").
# Bo sot dieu nay se tinh nham actions/setup-node, actions/setup-python,
# actions/setup-go la "roi vao fallback" trong khi thuc ra da duoc bao phu -
# da phat hien va sua loi nay truoc khi chay ban chinh thuc.
# gh_cli van giu lai trong danh sach (vo hai, pattern cua no la lenh shell
# "\bgh\s+\w" se khong bao gio khop 1 ten action nhu "actions/checkout").
covering_res = []
for r in RULES:
    if r["id"] == "any_action":
        continue
    for p in r["patterns"]:
        pat = p.replace("uses:\\s*", "")  # so khop truc tiep len TEN ACTION, bo tien to uses:
        covering_res.append(re.compile(pat, re.I))

USES_LINE_RE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.M)

# (repo, path) -> blob
blob_of = {}
with open(DATA / "files_ci.jsonl", encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        blob_of[(d["repo"], d["path"])] = d["blob"]

pols = []
with open(DATA / "policies_ci.jsonl", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        if not r.get("enforced") or r.get("uses_templating"):
            continue
        if not r.get("hosts"):
            continue
        pols.append(r)

print(f"[*] {len(pols)} policy co cuong che + allowlist doc duoc (cung corpus voi validate_static_rules.py)")

seen_files = set()
fallback_file_counter = Counter()   # action name -> so FILE khac nhau co dung
covered_file_counter = Counter()
action_to_repos = {}
n_no_text = 0

for p in pols:
    key = (p["repo"], p["path"])
    if key in seen_files:
        continue
    seen_files.add(key)
    blob = blob_of.get(key)
    if not blob:
        n_no_text += 1
        continue
    fp = DATA / "files" / blob
    try:
        txt = fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        n_no_text += 1
        continue

    actions_in_file = set()
    for m in USES_LINE_RE.finditer(txt):
        raw = m.group(1).strip().strip('"\'')
        if not raw or raw.startswith("./") or raw.startswith("docker://"):
            continue  # local/reusable workflow hoac docker image truc tiep - khac loai
        name = raw.split("@")[0].lower()  # bo version sau '@'
        actions_in_file.add(name)

    for name in actions_in_file:
        is_covered = any(rx.search(name) for rx in covering_res)
        if is_covered:
            covered_file_counter[name] += 1
        else:
            fallback_file_counter[name] += 1
            action_to_repos.setdefault(name, set()).add(p["repo"])

if n_no_text:
    print(f"[!] {n_no_text} file khong doc duoc, da bo qua")

print(f"\n[*] Tong so file workflow duy nhat da quet: {len(seen_files)}")
print(f"[*] Tong so ten action PHAN BIET roi vao fallback any_action: {len(fallback_file_counter)}")
print(f"[*] Tong so ten action PHAN BIET da duoc rule rieng bao phu: {len(covered_file_counter)}")

print("\n" + "=" * 78)
print("TOP 30 ACTION roi vao fallback any_action, sap theo SO REPO khac nhau dung")
print("=" * 78)
print(f"{'action':55s} {'#repo':>7s} {'#file':>7s}")
for name, repos in sorted(action_to_repos.items(), key=lambda kv: -len(kv[1]))[:30]:
    n_repo = len(repos)
    n_file = fallback_file_counter[name]
    print(f"{name:55s} {n_repo:7d} {n_file:7d}")

out = {
    "n_files_scanned": len(seen_files),
    "n_distinct_fallback_actions": len(fallback_file_counter),
    "n_distinct_covered_actions": len(covered_file_counter),
    "top_fallback_actions": [
        {"action": name, "n_repo": len(repos), "n_file": fallback_file_counter[name]}
        for name, repos in sorted(action_to_repos.items(), key=lambda kv: -len(kv[1]))
    ],
}
Path(str(_P.data("measurement/any_action_fallback_frequency.json"))).write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8"
)
print("\n>>> measurement/any_action_fallback_frequency.json")
