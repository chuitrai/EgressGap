#!/usr/bin/env python3
"""
evaluate_parametric_evidence.py - Buoc 3: domain RESOLVED tu parametric_targets.json
khong chi la "trich duoc", ma la BANG CHUNG that (R quan sat tu chinh argument cua
lenh) de doi chieu voi allowlist DA KHAI BAO (I) cua tung policy.

Y tuong giong validate_static_rules.py (do "dong thuan giua luat va allowlist"), nhung
o day dung DOMAIN THAT trich tu chinh dong lenh, khong phai domain SUY tu ten pattern.

QUAN TRONG - 2 dieu chinh sau khi review (khong duoc bo qua):

1. RAW vs CLEAN. 74,6% cua corpus PARAMETRIC la repo tu-test cua step-security
   (xem quantify_test_repo_noise.py) - nhung workflow nay TU KHAI BAO allowlist de
   kiem tra chinh Harden-Runner, nen "confirmed" gan nhu chac chan xay ra (tautology),
   khong phai bang chung ve nhu cau build that. Script nay tinh CA HAI: "raw" (bao
   gom noise) va "clean" (da loai) - LUON dan bang so "clean" khi bao cao.

2. Coverage cao KHONG co nghia extraction chinh xac. Vi cac policy nhin thay o day
   deu dang enforcing/block (chi crawl duoc policy dang "song"), day la SELECTION
   BIAS: khong thay duoc policy da hong vi thieu domain (da bi sua hoac bi xoa truoc
   khi crawl). Vi vay diem dang quan tam la SO LUONG MISSING (bao nhieu domain can
   ma khong khai bao), khong phai % coverage - dan dau bao cao bang so missing.

PHAM VI: day la ground truth CHIEU RECALL (domain can -> co khai bao khong) cho tap
con curl/wget/git-clone/helm nhin thay duoc. KHONG lien quan va KHONG validate con so
over-declaration 67% (chieu NGUOC LAI: domain khai bao -> co can khong) - hai con so
do hai huong khac nhau, khong duoc goi 1 cai la "validate" cai kia.

CHAY
    uv run python measurement/evaluate_parametric_evidence.py
"""
from teep import paths as _P
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TARGETS = Path(str(_P.data("measurement/parametric_targets.json")))
POLICIES = Path(str(_P.data("data/policies_ci.jsonl")))
OUT = Path(str(_P.data("measurement/parametric_evidence_evaluation.json")))


def load_declared_hosts():
    """policy_key (repo,path,job) -> list host da khai bao (I), CUNG dieu kien loc
    voi cac script khac trong du an de nhat quan."""
    out = {}
    with POLICIES.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("enforced") or r.get("uses_templating"):
                continue
            hosts = r.get("hosts") or []
            if not hosts:
                continue
            out[(r["repo"], r["path"], r["job"])] = [h.lower() for h in hosts]
    return out


def host_matches(domain, declared_hosts):
    d = domain.lower()
    for h in declared_hosts:
        if h == d:
            return True
        if h.startswith("*.") and d.endswith(h[1:]):
            return True
    return False


def evaluate(resolved_rows, declared):
    n_total = len(resolved_rows)
    n_confirmed = 0
    n_missing = 0
    n_no_declared_data = 0
    missing_domain_freq = Counter()
    missing_examples = defaultdict(list)
    per_policy = defaultdict(lambda: {"resolved": 0, "confirmed": 0, "missing": 0})

    for r in resolved_rows:
        key = (r["repo"], r["workflow"], r["job"])
        hosts = declared.get(key)
        per_policy[key]["resolved"] += 1
        if hosts is None:
            n_no_declared_data += 1
            continue
        if host_matches(r["resolved_domain"], hosts):
            n_confirmed += 1
            per_policy[key]["confirmed"] += 1
        else:
            n_missing += 1
            per_policy[key]["missing"] += 1
            missing_domain_freq[r["resolved_domain"]] += 1
            if len(missing_examples[r["resolved_domain"]]) < 3:
                missing_examples[r["resolved_domain"]].append(
                    f"{r['repo']}:{r['workflow']}#{r['job']} :: {r['raw_line'][:80]}"
                )

    n_policies_with_gap = sum(1 for v in per_policy.values() if v["missing"] > 0)
    n_policies_fully_confirmed = sum(
        1 for v in per_policy.values() if v["missing"] == 0 and v["confirmed"] > 0
    )
    denom = n_confirmed + n_missing
    return {
        "n_resolved_evidence_total": n_total,
        "n_no_declared_data": n_no_declared_data,
        "n_confirmed_in_declared_allowlist": n_confirmed,
        "n_missing_from_declared_allowlist": n_missing,
        "evidence_coverage_pct": round(100 * n_confirmed / denom, 1) if denom else None,
        "n_policies_with_resolved_evidence": len(per_policy),
        "n_policies_fully_confirmed": n_policies_fully_confirmed,
        "n_policies_with_at_least_1_gap": n_policies_with_gap,
        "top_missing_domains": missing_domain_freq.most_common(30),
        "missing_examples": {k: v for k, v in list(missing_examples.items())[:30]},
    }


def main():
    data = json.loads(TARGETS.read_text(encoding="utf-8"))
    resolved_rows_raw = [r for r in data["rows"] if r["resolution"] == "RESOLVED"]
    resolved_rows_clean = [r for r in resolved_rows_raw if not r.get("is_test_repo_noise")]
    declared = load_declared_hosts()

    raw_eval = evaluate(resolved_rows_raw, declared)
    clean_eval = evaluate(resolved_rows_clean, declared)

    print("=" * 78)
    print("S1 EVALUATION: RESOLVED evidence doi chieu allowlist da khai bao")
    print("=" * 78)
    print("QUAN TRONG - doc theo thu tu nay, KHONG dan bang % coverage:")
    print(f"""
  Trong {clean_eval['n_resolved_evidence_total']} dich duoc trich tinh (tap SACH, da
  loai repo tu-test cua step-security), {clean_eval['n_missing_from_declared_allowlist']}
  ({100*clean_eval['n_missing_from_declared_allowlist']/clean_eval['n_resolved_evidence_total']:.1f}%)
  KHONG co trong allowlist cua chinh policy chua lenh do. Vi cac policy nay dang o
  enforcing/block mode, 1 dich vang mat nghia la MOT trong ba kha nang: (a) nhanh
  code khong bao gio chay trong lan crawl nay, (b) loi trich xuat con sot, hoac
  (c) policy that su se fail neu nhanh do chay. Ca 3 deu can xem tay, khong suy
  duoc chi tu static evidence.
""")
    print(f"  --- Ban RAW (n={raw_eval['n_resolved_evidence_total']}, LAN CA repo tu-test - CO SELECTION BIAS ---")
    print(f"      Coverage {raw_eval['evidence_coverage_pct']}% GAN NHU TAUTOLOGY: phan lon la workflow")
    print(f"      tu-test cua step-security, TU KHAI BAO allowlist de kiem tra chinh no -")
    print(f"      confirmed gan-chac-chan, khong phai bang chung ve nhu cau build that.")
    print()
    print(f"  --- Ban SACH (n={clean_eval['n_resolved_evidence_total']}, da loai repo tu-test) - SO NEN DUNG ---")
    print(f"      Confirmed: {clean_eval['n_confirmed_in_declared_allowlist']}   "
          f"Missing: {clean_eval['n_missing_from_declared_allowlist']}   "
          f"Coverage: {clean_eval['evidence_coverage_pct']}%")
    print(f"      Policy co evidence: {clean_eval['n_policies_with_resolved_evidence']}   "
          f"Fully confirmed: {clean_eval['n_policies_fully_confirmed']}   "
          f"Co gap: {clean_eval['n_policies_with_at_least_1_gap']}")
    print()
    print("  --- top domain MISSING (ban SACH) ---")
    for dom, n in clean_eval["top_missing_domains"][:15]:
        print(f"    {dom:<45}{n}")
    print()
    print("  LUU Y PHAM VI (khong overclaim): day la GROUND TRUTH CHIEU RECALL")
    print("  (domain can -> co khai bao khong) cho tap con curl/wget/git-clone/helm")
    print("  NHIN THAY duoc. No KHONG lien quan va KHONG validate con so")
    print("  over-declaration 67%% (chieu NGUOC LAI: domain khai bao -> co can khong).")

    out = {
        "summary_raw": raw_eval,
        "summary_clean": clean_eval,
        "note": (
            "raw = tat ca RESOLVED evidence (bao gom repo tu-test cua step-security, "
            "74.6% cua corpus PARAMETRIC - xem quantify_test_repo_noise.py). "
            "clean = da loai cac repo/workflow do, la ban NEN DUNG de bao cao. "
            "Coverage o day chi do CHIEU RECALL (domain can -> khai bao), KHONG "
            "phai precision cua allowlist va KHONG validate over-declaration 67%."
        ),
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Da ghi {OUT}")


if __name__ == "__main__":
    main()
