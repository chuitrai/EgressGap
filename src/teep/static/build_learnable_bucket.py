#!/usr/bin/env python3
"""
build_learnable_bucket.py - Task 4, buoc 1: gate-check tan suat domain de xac
dinh vung "hoc duoc" (learnable) cho thu nghiem decision tree.

VI SAO CAN BUOC NAY (xem plan_b_deep_research_prompt.md, Task 4 + Q2):
    Khong phai domain nao cung hop ly de "hoc" bang ML:
    - Domain qua PHO BIEN (>400/698 repo, vd github.com) - moi repo deu can,
      khong co gi de phan biet (label gan nhu hang so) - hoc vo nghia.
    - Domain qua HIEM (<5/698 repo) - qua it duong duong duong tinh (positive)
      de bat ky model nao (ke ca cay nong) hoc duoc pattern dang tin cay,
      chi hoc thuoc long nhieu (overfit tuyet doi).
    - Vung GIUA (50-400 va 5-50) la noi con lai du du lieu de hoc nhung van
      con thong tin phan biet (khong phai hang so).
    Nguong 4 khoang (>400/50-400/5-50/<5) LA HEURISTIC TU DE XUAT, khong phai
    quy uoc hoc thuat chuan - neo ly thuyet gan nhat la head/tail-label
    (Wei et al., arXiv:2210.03968), trinh bay dung nhu vay trong paper, KHONG
    trich nhu 1 threshold da duoc cong nhan.

CACH TINH "so repo co domain X": dem SO REPO PHAN BIET (khong phai so lan
xuat hien) co domain X trong declared_hosts (allowlist THAT da khai bao,
union nhieu file enforced/khong-templated cua repo do - dung lai truong
declared_hosts co san trong taskb_selected_repos.json, KHONG tinh lai tu dau).

INPUT
    measurement/taskb_selected_repos.json  (698 repo, moi repo co declared_hosts)

OUTPUT
    measurement/domain_frequency_buckets.json
        { ">400": [...], "50-400": [...], "5-50": [...], "<5": [...],
          "n_repo_total": int, "n_domain_total": int }

CHAY
    uv run python measurement/build_learnable_bucket.py
"""
from teep import paths as _P
import json
import re
from collections import defaultdict
from pathlib import Path

SRC = Path(str(_P.data("measurement/taskb_selected_repos.json")))
OUT = Path(str(_P.data("measurement/domain_frequency_buckets.json")))

# Loai IP thuan, entry SRV-style (_proto._tcp.host), va chuoi rong khoi thong
# ke tan suat domain - day la gate-check cho TEN MIEN, khong phai IP/SRV record.
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# v1.1 - phat hien qua chinh lan chay dau (bucket 5-50 co "${{", "}}",
# "env.allowed_endpoints", "from", "the" lot vao nhu the la domain that!).
# Nguyen nhan: mot so policy co allowed-endpoints TRON MOT PHAN template
# (vd "github.com:443 ${{ env.EXTRA }} api.github.com:443") - co ve
# uses_templating chi bat truong hop CA CHUOI la template, khong bat truong
# hop template NAM GIUA danh sach host that. Bo loc chat hon: domain phai co
# it nhat 1 dau cham, chi gom chu/so/gach ngang/dau cham (cho phep tien to
# "*." cho wildcard), khong chua "_" (tru dong SRV da loai o tren), khong
# chua "{"/"}"/"$"/khoang trang. Day la loc o TANG PHAN TICH (khong sua duoc
# tu goc parse cua hr_crawl.py/taskb_select_repos.py trong pham vi script
# nay) - can bao lai cho Bao vi co the anh huong nhe den |I| cua Task 2
# (over-declaration) neu cac token rac nay lot vao declared_hosts o nhung
# repo khac.
DOMAIN_SHAPE_RE = re.compile(r"^\*?\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def is_domain_like(h):
    h = h.strip().lower()
    if not h or IP_RE.match(h):
        return False
    if h.startswith("_"):  # SRV-style: _https._tcp.xxx
        return False
    if "_" in h or "{" in h or "}" in h or "$" in h or " " in h:
        return False
    if not DOMAIN_SHAPE_RE.match(h):
        return False
    return True


def main():
    data = json.loads(SRC.read_text(encoding="utf-8"))
    repos = data["selected"]
    n_repo_total = len(repos)

    domain_repos = defaultdict(set)  # domain -> {repo, ...}
    for c in repos:
        repo = c["repo"]
        hosts = c.get("declared_hosts") or []
        for h in hosts:
            h = h.lower()
            if not is_domain_like(h):
                continue
            domain_repos[h].add(repo)

    buckets = {">400": [], "50-400": [], "5-50": [], "<5": []}
    for domain, rs in domain_repos.items():
        n = len(rs)
        if n > 400:
            key = ">400"
        elif n >= 50:
            key = "50-400"
        elif n >= 5:
            key = "5-50"
        else:
            key = "<5"
        buckets[key].append({"domain": domain, "n_repo": n})

    for key in buckets:
        buckets[key].sort(key=lambda d: -d["n_repo"])

    out = {
        "n_repo_total": n_repo_total,
        "n_domain_total": len(domain_repos),
        **{k: v for k, v in buckets.items()},
        "n_per_bucket": {k: len(v) for k, v in buckets.items()},
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")

    print(f"[*] Corpus: {n_repo_total} repo, {len(domain_repos)} domain phan biet")
    for k in [">400", "50-400", "5-50", "<5"]:
        print(f"    {k:8s}: {len(buckets[k])} domain")
    print(f">>> Da ghi {OUT}")
    print("\n[*] Vung 'hoc duoc' (5-50 repo) - dung cho Task 4:")
    for d in buckets["5-50"]:
        print(f"    {d['domain']:50s} {d['n_repo']}")


if __name__ == "__main__":
    main()
