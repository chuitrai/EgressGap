#!/usr/bin/env python3
"""
egress_lint.py - Policy linter cho egress allowlist trong GitHub Actions workflow.

DAY LA APPLICATION MUC 1. No lam dung mot viec:
doc allowlist trong workflow YAML, tinh xem no THUC SU cho phep bao nhieu dich,
va bao cao ty le chat (tightness).

Giong eslint, nhung cho network policy.

CHAY
    python egress_lint.py .github/workflows/ci.yml
    python egress_lint.py .github/workflows/          # ca thu muc
    python egress_lint.py ci.yml --required r_pip.json --fail-under 0.05

DUNG NHU GITHUB ACTION (muc dich cuoi cung):
    - uses: step-security/harden-runner@v2
      with: { egress-policy: audit }
    - uses: <you>/egress-lint@v1
      with: { fail-on-tightness-below: 0.05 }
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Windows: khi stdout bi redirect (> file) thi Python dung code page mac
# dinh (thuong la cp1252), khong encode duoc ten repo/file co ky tu ngoai
# ASCII (VD: chu Trung/Han trong ten repo that trong corpus). Ep UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

# ---- Namespace ma BEN THU BA dang ky duoc subdomain -----------------------
# Nguon: tai lieu dat ten cua tung nha cung cap. Danh sach dong, kiem tra duoc.
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

# Resolver DoH — neu co trong allowlist thi tap dich la TOAN INTERNET
DOH = {"dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
       "dns.nextdns.io", "doh.cleanbrowsing.org", "dns10.quad9.net",
       "chrome.cloudflare-dns.com", "mozilla.cloudflare-dns.com"}

# Endpoint tu khai la nhan du lieu (quy tac cu phap, chua hand-label)
SINK = re.compile(r"^(uploads?|hooks?|webhooks?|ingest|storage|blob|artifacts?)\.|"
                  r"\.(s3|r2|blob)\.", re.I)

# So dich uoc luong moi entry mo ra. Thay bang so do that tu Tranco khi co.
COTENANT_DEFAULT = 1
COTENANT_KNOWN = {
    "github.com": 1, "api.github.com": 1, "codeload.github.com": 1,
    "objects.githubusercontent.com": 4, "raw.githubusercontent.com": 4,
    "pypi.org": 8, "files.pythonhosted.org": 8,
    "registry.npmjs.org": 12, "registry.yarnpkg.com": 12,
    "index.docker.io": 15, "registry-1.docker.io": 15,
}
OPEN_NS_SIZE = 10 ** 6      # namespace mo: coi nhu khong gioi han
VENDOR_WC_SIZE = 50         # wildcard do mot to chuc kiem soat


def classify_wildcard(pattern):
    p = pattern.lower().lstrip("*").lstrip(".")
    p = re.sub(r"^[^.]*\*[^.]*\.", "", p)
    for suf, why in OPEN_NS.items():
        if p == suf or p.endswith("." + suf):
            return "open", suf, why
    return "vendor", p, ""


def expand(entry):
    """|expand(e)| — so dich entry nay thuc su mo ra."""
    host = entry.split(":")[0].lower()
    if host in DOH:
        return float("inf")
    if "*" in host:
        kind, _, _ = classify_wildcard(host)
        return OPEN_NS_SIZE if kind == "open" else VENDOR_WC_SIZE
    return COTENANT_KNOWN.get(host, COTENANT_DEFAULT)


def parse_allowlists(path):
    """Tim moi step harden-runner trong mot file workflow."""
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"
    out = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
            
        jobs_dict = doc.get("jobs")
        # Bỏ qua nếu file không có jobs hoặc jobs không phải là dictionary
        if not isinstance(jobs_dict, dict):
            continue
            
        for job_name, job in jobs_dict.items():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps") or []):
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
                out.append({"job": job_name, "policy": pol,
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
    ap.add_argument("path")
    ap.add_argument("--required", help="file JSON tu oracle_proxy.py")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="thoat 1 neu tightness thap hon nguong")
    a = ap.parse_args()

    required = None
    if a.required:
        d = json.loads(Path(a.required).read_text())
        required = d["required_set"]

    p = Path(a.path)
    files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    worst, n_pol = 1.0, 0

    for f in files:
        recs, err = parse_allowlists(f)
        if err or not recs:
            continue
        for rec in recs:
            n_pol += 1
            print("=" * 68)
            print(f"{f}  ::  job '{rec['job']}'")
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
