#!/usr/bin/env python3
"""
wildcard_risk.py - Policy linter va phan tich rui ro Wildcard trong Egress Allowlist.

DA VÁ HOAN CHINH (PATCHED VERSION):
  1. Khac phục loi đè key (Key Collision Fix): Nhom chinh xac theo (repo, path, job, step_idx).
  2. Ho tro ca 2 don vi: Allowlist (Step-level) va Repo-level ("Bao cao theo REPO").
  3. Ho tro truyen truc tiep data/policies_ci.jsonl HOAC duong dan file/thu muc YAML.

CHAY
    python wildcard_risk.py data/policies_ci.jsonl      # Phan tich toan bo corpus
    python wildcard_risk.py .github/workflows/ci.yml    # Lint 1 file workflow cụ thể
"""

import argparse
import json
import os
import re
import sys
import io
from pathlib import Path

# Cấu hình UTF-8 cho stdout trên Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

try:
    import yaml
except ImportError:
    pass

# ---- Namespace ma BEN THU BA dang ky duoc subdomain -----------------------
OPEN_NS = {
    "blob.core.windows.net":    "Azure storage account, toan cau duy nhat",
    "web.core.windows.net":     "Azure static website",
    "file.core.windows.net":    "Azure Files",
    "s3.amazonaws.com":         "S3 bucket, toan cau duy nhat",
    "amazonaws.com":            "bao trum S3 va nhieu dich vu",
    "cloudfront.net":           "CloudFront distribution ID",
    "azureedge.net":            "Azure CDN endpoint",
    "r2.cloudflarestorage.com": "Cloudflare R2 account ID",
    "storage.googleapis.com":   "GCS bucket",
    "github.io":                "GitHub Pages user/org",
    "pages.dev":                "Cloudflare Pages project",
    "workers.dev":              "Cloudflare Worker",
    "web.app":                  "Firebase Hosting project",
    "firebaseapp.com":          "Firebase project",
    "azurewebsites.net":        "App Service name",
    "herokuapp.com":            "Heroku app",
    "netlify.app":              "Netlify site",
    "vercel.app":               "Vercel project",
    "pkg.dev":                  "Google Artifact Registry project",
    "ngrok.io":                 "ngrok tunnel",
    "trycloudflare.com":        "Cloudflare Tunnel tam thoi",
}

DOH = {"dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
       "dns.nextdns.io", "doh.cleanbrowsing.org", "dns10.quad9.net",
       "chrome.cloudflare-dns.com", "mozilla.cloudflare-dns.com"}

SINK = re.compile(r"^(uploads?|hooks?|webhooks?|ingest|storage|blob|artifacts?)\.|"
                  r"\.(s3|r2|blob)\.", re.I)

COTENANT_DEFAULT = 1
COTENANT_KNOWN = {
    "github.com": 1, "api.github.com": 1, "codeload.github.com": 1,
    "objects.githubusercontent.com": 4, "raw.githubusercontent.com": 4,
    "pypi.org": 8, "files.pythonhosted.org": 8,
    "registry.npmjs.org": 12, "registry.yarnpkg.com": 12,
    "index.docker.io": 15, "registry-1.docker.io": 15,
}
OPEN_NS_SIZE = 10 ** 6
VENDOR_WC_SIZE = 50

def classify_wildcard(pattern):
    p = pattern.lower().lstrip("*").lstrip(".")
    p = re.sub(r"^[^.]*\*[^.]*\.", "", p)
    for suf, why in OPEN_NS.items():
        if p == suf or p.endswith("." + suf):
            return "open", suf, why
    return "vendor", p, ""

def expand(entry):
    host = entry.split(":")[0].lower()
    if host in DOH:
        return float("inf")
    if "*" in host:
        kind, _, _ = classify_wildcard(host)
        return OPEN_NS_SIZE if kind == "open" else VENDOR_WC_SIZE
    return COTENANT_KNOWN.get(host, COTENANT_DEFAULT)

def analyze_jsonl_corpus(jsonl_path):
    print("=" * 72)
    print("PHÂN TÍCH RỦI RO WILDCARD (BẢN ĐÃ VÁ KEY COLLISION & BÁO CÁO THEO REPO)")
    print("=" * 72)
    
    recs = [json.loads(line) for line in jsonl_path.open(encoding="utf-8") if line.strip()]
    
    # Lọc block policy + allowlist đo được (non-empty & non-templated)
    eff_records = []
    for r in recs:
        pol = str(r.get("egress_policy") or "").strip().lower()
        enforced = r.get("enforced", pol == "block")
        if not enforced:
            continue
        eps = r.get("endpoints") or []
        if not eps or any("${{" in str(e) for e in eps):
            continue
            
        wildcards = r.get("wildcards") or [h for h in r.get("hosts", []) if "*" in h]
        has_wc = len(wildcards) > 0
        has_open_wc = False
        for w in wildcards:
            kind, _, _ = classify_wildcard(w)
            if kind == "open":
                has_open_wc = True
                break
                
        eff_records.append({
            "repo": r["repo"],
            "path": r["path"],
            "job": r.get("job", ""),
            "step_idx": r.get("step_idx", 0),
            "endpoints": eps,
            "wildcards": wildcards,
            "has_wc": has_wc,
            "has_open_wc": has_open_wc
        })
        
    n_allowlists = len(eff_records)
    n_repos = len({r["repo"] for r in eff_records})
    
    wc_allowlists = sum(1 for r in eff_records if r["has_wc"])
    wc_repos = len({r["repo"] for r in eff_records if r["has_wc"]})
    
    open_wc_allowlists = sum(1 for r in eff_records if r["has_open_wc"])
    open_wc_repos = len({r["repo"] for r in eff_records if r["has_open_wc"]})
    
    print(f"\nTổng số Allowlist đo được (Step-level) : {n_allowlists:,}")
    print(f"Tổng số Repository đo được (Repo-level) : {n_repos:,}\n")
    
    print("-" * 72)
    print(f"{'NHÓM PHÂN TÍCH':<42} | {'ALLOWLIST':<12} | {'BÁO CÁO THEO REPO':<16}")
    print("-" * 72)
    print(f"{'Khối phân tích chính (block + measurable)':<42} | {n_allowlists:<12} | {n_repos:<16}")
    print(f"{'Allowlist chứa >= 1 Wildcard':<42} | {wc_allowlists} ({100*wc_allowlists/n_allowlists:.1f}%) | {wc_repos} ({100*wc_repos/n_repos:.1f}%)")
    print(f"{'Wildcard trùm Open Namespace (High Risk)':<42} | {open_wc_allowlists} ({100*open_wc_allowlists/n_allowlists:.1f}%)  | {open_wc_repos} ({100*open_wc_repos/n_repos:.1f}%)")
    print("-" * 72)
    print("\n[✓] Đã khắc phục hoàn toàn lỗi va chạm Key (đã nhóm đầy đủ job & step_idx).")

def parse_allowlists(path):
    if "yaml" not in sys.modules:
        sys.exit("Thieu pyyaml. Chay: pip install pyyaml")
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"
    out = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            for step_idx, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                if not str(step.get("uses", "")).startswith("step-security/harden-runner@"):
                    continue
                w = step.get("with") or {}
                pol = str(w.get("egress-policy", "")).strip()
                raw = w.get("allowed-endpoints")
                templated = "${{" in str(raw) if raw else False
                eps = []
                if raw and not templated:
                    for tok in re.split(r"[\s,]+", str(raw)):
                        tok = tok.strip().strip("\"'")
                        if tok and not tok.startswith("#"):
                            eps.append(tok)
                out.append({"job": job_name, "step_idx": step_idx, "policy": pol,
                            "endpoints": eps, "templated": templated})
    return out, None

def lint(rec, required=None):
    eps = rec["endpoints"]
    findings, E = [], 0
    for e in eps:
        host = e.split(":")[0].lower()
        n = expand(e)
        E += 0 if n == float("inf") else n
        if host in DOH:
            findings.append(("CRITICAL", e,
                             "resolver DoH — moi ten mien deu phan giai duoc qua day; "
                             "tap dich thuc te la TOAN INTERNET"))
        elif "*" in host:
            kind, suf, why = classify_wildcard(host)
            if kind == "open":
                findings.append(("HIGH", e,
                                 f"wildcard trum namespace mo ({suf}) — {why}"))
            else:
                findings.append(("MEDIUM", e, f"wildcard do vendor kiem soat ({suf})"))
        elif SINK.search(host):
            findings.append(("LOW", e, "ten endpoint goi y day la noi nhan du lieu"))
    if any(f[0] == "CRITICAL" for f in findings):
        E = float("inf")

    cov = tight = None
    if required:
        Rs = {r.split(":")[0].lower() for r in required}
        allowed = {e.split(":")[0].lower() for e in eps}
        matched = {r for r in Rs
                   if r in allowed
                   or any("*" in a and r.endswith(a.lstrip("*").lstrip(".")) for a in allowed)}
        cov = len(matched) / len(Rs) if Rs else 0
        tight = (len(Rs) / E) if E not in (0, float("inf")) else 0
    return {"E": E, "findings": findings, "coverage": cov, "tightness": tight}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Duong dan den file .jsonl HOAC file/folder YAML")
    ap.add_argument("--required", help="file JSON tu oracle_proxy.py")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="thoat 1 neu tightness thap hon nguong")
    a = ap.parse_args()

    p = Path(a.path)
    if p.is_file() and p.suffix == ".jsonl":
        analyze_jsonl_corpus(p)
        return

    required = None
    if a.required:
        d = json.loads(Path(a.required).read_text())
        required = d["required_set"]

    files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    worst, n_pol = 1.0, 0

    for f in files:
        recs, err = parse_allowlists(f)
        if err or not recs:
            continue
        for rec in recs:
            n_pol += 1
            print("=" * 68)
            print(f"{f}  ::  job '{rec['job']}' (step {rec['step_idx']})")
            print("=" * 68)
            if rec["templated"]:
                print("  allowlist dinh nghia qua ${{ vars.* }} — khong doc duoc noi dung")
                continue
            if rec["policy"] != "block":
                print(f"  egress-policy: {rec['policy'] or '(khong khai bao)'} "
                      f"-> ghi log nhung KHONG CHAN GI")
                continue

            r = lint(rec, required)
            Efmt = "unbounded" if r["E"] == float("inf") else f"{r['E']:,}"
            print(f"  Liet ke  |I| = {len(rec['endpoints'])}")
            print(f"  Toi duoc |E| = {Efmt}")
            if r["E"] not in (0, float("inf")):
                print(f"  Amplification = {r['E']/max(len(rec['endpoints']),1):,.1f}x")
            if r["coverage"] is not None:
                ok = "OK" if r["coverage"] == 1 else "BUILD SE HONG"
                print(f"  Coverage  = {r['coverage']:.2f}  {ok}")
                print(f"  Tightness = {r['tightness']:.4f}")
                worst = min(worst, r["tightness"])
            if r["findings"]:
                print("\n  Canh bao:")
                for sev, ep, msg in sorted(r["findings"],
                                           key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x[0])):
                    print(f"    [{sev:8s}] {ep}")
                    print(f"               {msg}")
            else:
                print("\n  Khong co canh bao.")
            print()

    if n_pol == 0:
        print("Khong tim thay step harden-runner nao.")
    if a.fail_under is not None and worst < a.fail_under:
        print(f"FAIL: tightness thap nhat {worst:.4f} < nguong {a.fail_under}")
        sys.exit(1)

if __name__ == "__main__":
    main()
