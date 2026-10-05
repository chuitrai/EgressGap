#!/usr/bin/env python3
"""
extract_rlog_v2.py - Rewrite R_log extraction theo yeu cau cua Bao (2026-09-07):
KHONG con grep 'https?://...' vo dieu kien roi loc hau ky. Dinh nghia moi:

    R_log = domain co BANG CHUNG DNS/network audit RO RANG tu chinh Harden-Runner,
    KHONG phai domain xuat hien trong text (markdown, boilerplate, policy echo).

2 pattern bang chung DUY NHAT duoc chap nhan (tim thay qua doc truc tiep log that):
    1. "[dns-request] ... exe=<proc> ... domain=<domain>. matchedPolicy=<X>"
       -> co gan process (exe=) -> dung de phan WORKLOAD vs TOOLING.
    2. "domain resolved: <domain>., ip address: <ip>, TTL: <n>"
       -> KHONG co truong exe -> phan loai WORKLOAD/TOOLING theo ten mien
          (*.stepsecurity.io = TOOLING, con lai = WORKLOAD).

MOI thu khac (allowed-endpoints:, Endpoints:map[, markdown, runner-image banner,
Node deprecation, license...) TU DONG bi loai vi KHONG khop 2 pattern tren -
khong can danh sach blocklist rieng cho boilerplate.

TOOLING = ha tang cua chinh Harden-Runner (exe=agent, hoac domain *.stepsecurity.io
khi khong co exe). Day la traffic THAT nhung KHONG PHAI dependency cua workload.
WORKLOAD = phan con lai -> dung lam R_exec.

OUTPUT: measurement/taskb_run_data/taskb_step2_urls_v2.json
    { repo: [ {domain, classification: WORKLOAD|TOOLING, evidence: REAL_DNS|REAL_DNS_REQUEST,
               exe: str|null, n_occurrences: int} ] }

Biet gioi han (chua dong): 2 pattern text khong duoc bat (false negative da xac nhan
qua doi soat 30 mau): dong kieu NuGet "Installed X from <url>" va dong Harden-Runner
"Fetching custom detection rules api_url=..." khong co dang [dns-request]/"domain
resolved". Neu can tang recall, them pattern moi cho 2 dang nay la buoc tiep theo.
"""
from teep import paths as _P
import json
import re
from pathlib import Path
from collections import defaultdict

LOGS_DIR = Path(str(_P.data("measurement/taskb_run_data/logs")))
OUT = Path(str(_P.data("measurement/taskb_run_data/taskb_step2_urls_v2.json")))

DNS_REQUEST_RE = re.compile(
    r"\[dns-request\].*?\bexe=(\S+).*?\bdomain=([a-zA-Z0-9.-]+?)\.?\s+matchedPolicy="
)
DOMAIN_RESOLVED_RE = re.compile(
    r"domain resolved:\s*([a-zA-Z0-9.-]+?)\.,\s*ip address:"
)

TOOLING_SUFFIX_RE = re.compile(r"\.stepsecurity\.io$", re.I)

# v2.1 (2026-09-07) - phat hien qua chinh buoc do Precision/Recall/F1 cua S1 vs
# R_exec: static_rules.json (v4.1) da gan rule 'github_actions_runtime_infra'
# (ecosystem=tooling) cho ha tang bao cao ket qua job CUA CHINH GitHub Actions
# runner (actions-results-receiver-production.githubapp.com + 20 shard
# productionresultssaN.blob.core.windows.net) - xuat hien BAT KE workflow lam
# gi, khong phai dependency cua workload. NHUNG ban trich R_exec nay (v2, truoc
# sua) chua biet domain nay la tooling -> van tinh WORKLOAD -> tao ra ~1.771
# luot "FN gia" cho S1 (S1 dung khi KHONG du doan domain nay, nhung R_exec vi
# khong loai no nen van tinh la "domain can nhung S1 thieu"). Sua de 2 phia
# (S1 D_static va R_exec) dung CHUNG 1 dinh nghia tooling, khong lech nhau -
# giu dung tinh than da ap dung cho *.stepsecurity.io tu ban v2 dau tien.
#
# v2.2 (2026-09-12) - 2 quyet dinh tooling cua Bao, dua tren doc truc tiep log
# that (xem static_rules.json changelog_v4_3 de biet day du bang chung):
#   - results-receiver.actions.githubusercontent.com (228 FN, cao nhat corpus
#     truoc khi sua): dong debug cua chinh actions-runner cho thay day la Twirp
#     API CacheService cua RUNNER ("##[debug][Request] FinalizeCacheEntryUpload
#     https://results-receiver.actions.githubusercontent.com/twirp/github.
#     actions.results.api.v1.CacheService/..."), xuat hien ca o workflow KHONG
#     dung actions/cache tuong minh (vd OpenSSF Scorecard, npm publish/
#     attestation) - truoc day duoc gan nham vao rule workload
#     'actions_cache_artifact' (dieu kien 'uses: actions/cache...'), nay xoa
#     rule do va gop domain nay vao day.
#   - run-actions-{1,2,3}-azure-eastus.actions.githubusercontent.com (32 FN):
#     xac nhan qua log la ha tang OIDC/token-exchange cua actions-runner (luon
#     xuat hien cung token.actions.githubusercontent.com/api.github.com trong
#     luong publish/attestation), khong phai dependency cua workload.
GH_RUNTIME_INFRA_RE = re.compile(
    r"^(actions-results-receiver-production\.githubapp\.com"
    r"|productionresultssa\d+\.blob\.core\.windows\.net"
    # phat hien THEM 1 lop nua cua cung 1 hien tuong khi doi soat lai FN sau
    # khi sua lop dau: "hosted-compute-watchdog-prod-{vung}-{shard}.githubapp.com"
    # va "hosted-compute-request-orchestrator-prod-{vung}-{shard}.githubapp.com"
    # - kenh watchdog/orchestrator cua CHINH ha tang GitHub-hosted runner, xuat
    # hien tren moi job chay tren hosted runner bat ke workflow lam gi (khong
    # phai dependency cua workload). KHONG gom 2 domain "glb-*-public-internal.
    # githubapp.com" (chi thay 1 lan/domain, chua ro quy luat, de rieng lam
    # nhieu chua phan loai thay vi doan bua).
    r"|hosted-compute-(watchdog|request-orchestrator)-prod-[a-z0-9-]+\.githubapp\.com"
    # v2.2: CacheService (Twirp API) + OIDC/token-exchange cua actions-runner.
    r"|results-receiver\.actions\.githubusercontent\.com"
    r"|run-actions-\d+-azure-eastus\.actions\.githubusercontent\.com)$",
    re.I,
)


def classify(domain, exe):
    if exe == "agent":
        return "TOOLING"
    # BUG tu phat hien khi doi soat FN: dieu kien "exe is None" o day sai - lam
    # domain *.stepsecurity.io bi tinh nham WORKLOAD neu no duoc quan sat qua
    # dong [dns-request] CO exe (vd exe=systemd-resolve) thay vi dong
    # "domain resolved:" (khong co exe). Suffix stepsecurity.io la dac trung
    # CUA DOMAIN, khong lien quan exe nao trigger - phai kiem KHONG DIEU KIEN.
    if TOOLING_SUFFIX_RE.search(domain):
        return "TOOLING"
    if GH_RUNTIME_INFRA_RE.match(domain):
        # ha tang bao cao ket qua job cua CHINH GitHub Actions runner - xuat
        # hien bat ke exe nao trigger DNS (da thay ca systemd-resolve lan tien
        # trinh node cua actions-runner) nen kiem tra rieng theo domain, khong
        # theo exe nhu 2 nhanh tren.
        return "TOOLING"
    return "WORKLOAD"


def main():
    # xay lai dung anh xa safe_repo -> repo that (thay vi doan tach chuoi, vi
    # ten repo/org co the tu chua "_" - dung chinh danh sach 609 repo da chon
    # de tra nguoc chinh xac, khop dung logic `tr '/' '_'` cua bash script)
    selected = json.loads(Path(str(_P.data("measurement/taskb_selected_repos.json"))).read_text(encoding="utf-8"))["selected"]
    safe_to_real = {c["repo"].replace("/", "_"): c["repo"] for c in selected}

    result = {}
    n_repo_with_evidence = 0
    n_repo_total = 0
    for repo_dir in sorted(LOGS_DIR.iterdir()):
        extracted = repo_dir / "extracted"
        if not extracted.exists():
            continue
        n_repo_total += 1
        repo = safe_to_real.get(repo_dir.name, repo_dir.name)
        agg = defaultdict(lambda: {"classification": None, "evidence": None, "exe": None, "n_occurrences": 0})
        for txt_file in extracted.rglob("*.txt"):
            try:
                text = txt_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in DNS_REQUEST_RE.finditer(text):
                exe, domain = m.group(1), m.group(2).lower().rstrip(".")
                cls = classify(domain, exe)
                e = agg[domain]
                e["n_occurrences"] += 1
                e["evidence"] = "REAL_DNS_REQUEST"
                e["exe"] = exe
                e["classification"] = cls
            for m in DOMAIN_RESOLVED_RE.finditer(text):
                domain = m.group(1).lower().rstrip(".")
                e = agg[domain]
                e["n_occurrences"] += 1
                if e["evidence"] is None:
                    e["evidence"] = "REAL_DNS"
                    e["classification"] = classify(domain, None)
        if agg:
            n_repo_with_evidence += 1
        # dung ten repo THAT (co "/") lam key - khop dung format
        # taskb_step2_urls.json cu de taskb_compare.py doc duoc ma khong sua gi them
        result[repo] = [
            {"domain": d, **v} for d, v in sorted(agg.items())
        ]

    OUT.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"n_repo_total (co extracted/): {n_repo_total}")
    print(f"n_repo_with_dns_evidence (>=1 domain WORKLOAD hoac TOOLING): {n_repo_with_evidence}")
    print(f"Da ghi {OUT}")


if __name__ == "__main__":
    main()
