#!/usr/bin/env python3
"""
taskb_select_repos.py - Task B, Buoc 0: chon 20 repo thu nghiem cho cau hoi
"Actions run log co dung duoc lam R (ground truth) o quy mo lon khong?"

KHONG lay ngau nhien - loc theo dung 4 tieu chi thay dua ra, ca 4 deu bat buoc:

  1. KHONG thuoc 12 repo noise cua he sinh thai step-security (xem
     quantify_test_repo_noise.py) - neu khong, "log" ta doc duoc se la log cua
     chinh cac workflow demo/test cua step-security, khong phai build that.
  2. Public - repos_ci.jsonl duoc dung tu GitHub Code Search API, ve nguyen tac
     endpoint nay chi index code trong repo PUBLIC (repo private chi xuat hien
     trong ket qua search neu chinh token dang goi so huu/duoc moi vao repo do).
     Corpus nay crawl bang token rieng cua du an, khong so huu cac repo trong
     ket qua -> gia dinh hop ly la 100% public. VAN NEN xac nhan lai bang
     `gh repo view {repo} --json isPrivate` cho dung 20 repo cuoi cung o Buoc 1
     (re, khong ton them round-trip vi da goi gh api o buoc do).
  3. Co push trong 90 ngay gan day - dieu kien QUAN TRONG NHAT theo thay: GitHub
     xoa log Actions sau 90 ngay (mac dinh retention). Repo it hoat dong se
     KHONG con log de tai, va se bi hieu nham la "API khong dung duoc" trong
     khi thuc ra chi la "khong con gi de tai".
  4. Da dang he sinh thai (npm/pip/go/docker/...) - suy tu domain DA KHAI BAO
     trong allowlist cua chinh repo do (dung lai bang anh xa domain->ecosystem
     cua static_rules.json) - day cung chinh la tin hieu can de Buoc 3 (doi
     chieu R_log voi I) co y nghia: neu repo khong co domain nao thuoc 1
     ecosystem cu the trong I, khong the noi "R_log tim duoc domain ecosystem
     do hay khong" mot cach cong bang.

NGOAI RA (khong nam trong 4 tieu chi cua thay nhung can de ket qua sach):
  - Loai archived=true (repo ngung hoat dong, du push gan day - hiem nhung de phong).
  - Loai fork=true khi co the (fork thuong sao chep y het policy cua upstream,
    lam giam tinh doc lap cua mau - uu tien repo goc, chi lay fork neu khong
    du 20 repo goc dap ung dieu 3+4).
  - Khu trung lap allowlist y het nhau (cung "tap host" - dung lai dinh nghia
    cua analyze.py sec_dedup): 2 repo dung chung 1 allowlist y het (thuong la
    bot tu dong them harden-runner hang loat) chi tinh la 1 "mau doc lap".

CHAY
    python measurement/taskb_select_repos.py            # 20 repo, da dang (mac dinh)
    python measurement/taskb_select_repos.py --all       # TOAN BO repo sach (bo cap 20,
                                                          # bo buoc chon da dang), van
                                                          # loai noise + push>90 ngay + dedup
    python measurement/taskb_select_repos.py --limit 300 # gioi han so khac 20
"""
from teep import paths as _P
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

pass  # sys.path hack removed: package imports via teep.*
from teep.scoping.quantify_test_repo_noise import is_noise_repo  # noqa: E402

REPOS = Path(str(_P.data("data/repos_ci.jsonl")))
POLICIES = Path(str(_P.data("data/policies_ci.jsonl")))
STATIC_RULES = Path(str(_P.config("static_rules.json")))
OUT_JSON = Path(str(_P.data("measurement/taskb_selected_repos.json")))

WINDOW_DAYS = 90
TARGET_N = 20

# thu tu uu tien khi 1 repo khop nhieu ecosystem cung luc (chon 1 lam "primary"
# de xep vao 1 o trong bang da dang) - uu tien cac ecosystem thay neu ro
# (npm/pip/go/docker) truoc, con lai xep sau.
ECOSYSTEM_PRIORITY = [
    "python", "javascript", "go", "container", "rust", "java", "ruby", "iac",
    "system", "github", "ci-tools", "security", "supply-chain",
]


def build_domain_ecosystem_map():
    data = json.loads(STATIC_RULES.read_text(encoding="utf-8"))
    m = {}
    for rule in data["rules"]:
        eco = rule["ecosystem"]
        for d in rule["domains"]:
            # domain co the map nhieu ecosystem (vd github.com dung cho ca
            # checkout va gh_cli) - giu ecosystem DAU TIEN gap (uu tien rule
            # xuat hien truoc trong file, tuc rule cu the hon rule "any_action"
            # o cuoi).
            m.setdefault(d.lower(), eco)
    return m


def classify_repo_ecosystems(hosts, dom2eco):
    """Tra ve Counter ecosystem -> so host khop, dung host CHINH XAC (khong
    wildcard-match mo rong, vi muc dich la phan loai tho, khong can chinh xac
    tuyet doi)."""
    from collections import Counter
    c = Counter()
    for h in hosts:
        h = h.lower()
        if h in dom2eco:
            c[dom2eco[h]] += 1
            continue
        # wildcard trong allowlist, vd *.pypi.org -> thu khop phan sau dau cham
        if h.startswith("*."):
            base = h[2:]
            if base in dom2eco:
                c[dom2eco[base]] += 1
    return c


def load_repos_meta():
    meta = {}
    with REPOS.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            meta[r["repo"]] = r
    return meta


def load_eff_hosts_by_repo():
    """repo -> (union host_set, list cac (path,job,hosts) rieng biet, host_set
    dai dien de khu trung lap theo dung tieu chi cua analyze.sec_dedup)."""
    by_repo = defaultdict(lambda: {"hosts": set(), "n_policies": 0, "policy_host_sets": []})
    with POLICIES.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            ep = (r.get("egress_policy") or "").strip()
            enforced = r.get("enforced")
            if enforced is None:
                enforced = ep == "block"
            hosts = r.get("hosts") or []
            templated = r.get("uses_templating", False)
            if not enforced or templated or not hosts:
                continue
            hs = frozenset(h.lower() for h in hosts)
            d = by_repo[r["repo"]]
            d["hosts"] |= hs
            d["n_policies"] += 1
            d["policy_host_sets"].append(hs)
    return by_repo


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true",
                     help="Lay TOAN BO repo sach (bo cap so luong va buoc chon da dang "
                          "theo ecosystem). Van giu loc noise/archived/90-ngay/dedup.")
    ap.add_argument("--limit", type=int, default=None,
                     help="So repo muon lay (mac dinh 20 neu khong dung --all).")
    return ap.parse_args()


def main():
    args = parse_args()
    run_all = args.all
    target_n = None if run_all else (args.limit or TARGET_N)

    dom2eco = build_domain_ecosystem_map()
    repos_meta = load_repos_meta()
    eff_by_repo = load_eff_hosts_by_repo()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=WINDOW_DAYS)

    print("=" * 78)
    label = "TOAN BO repo sach" if run_all else f"chon {target_n} repo"
    print(f"TASK B - BUOC 0: {label} (cutoff push >= {cutoff.date()}, "
          f"hom nay {now.date()})")
    print("=" * 78)

    candidates = []
    n_total = len(eff_by_repo)
    n_drop_noise = n_drop_meta_missing = n_drop_archived = n_drop_old = n_drop_no_eco = 0

    for repo, d in eff_by_repo.items():
        if is_noise_repo(repo):
            n_drop_noise += 1
            continue
        meta = repos_meta.get(repo)
        if not meta:
            n_drop_meta_missing += 1
            continue
        if meta.get("archived"):
            n_drop_archived += 1
            continue
        pushed_at = meta.get("pushed_at")
        if not pushed_at:
            n_drop_meta_missing += 1
            continue
        try:
            pushed_dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        except ValueError:
            n_drop_meta_missing += 1
            continue
        if pushed_dt < cutoff:
            n_drop_old += 1
            continue

        eco_counts = classify_repo_ecosystems(d["hosts"], dom2eco)
        if not eco_counts:
            if not run_all:
                # chi bat buoc co ecosystem nhan dien duoc khi con phai CHON DA
                # DANG (--all thi khong can, van giu repo, gan nhan "unknown")
                n_drop_no_eco += 1
                continue
            primary_eco = "unknown"
        else:
            primary_eco = min(
                eco_counts.items(),
                key=lambda kv: (ECOSYSTEM_PRIORITY.index(kv[0])
                                 if kv[0] in ECOSYSTEM_PRIORITY else 999, -kv[1]),
            )[0]

        candidates.append({
            "repo": repo,
            "pushed_at": pushed_at,
            "days_since_push": (now - pushed_dt).days,
            "is_fork": bool(meta.get("is_fork")),
            "stars": meta.get("stars", 0),
            "language": meta.get("language"),
            "owner_type": meta.get("owner_type"),
            "n_declared_hosts": len(d["hosts"]),
            "declared_hosts": sorted(d["hosts"]),
            "n_policies_eff": d["n_policies"],
            "ecosystems_matched": dict(eco_counts),
            "primary_ecosystem": primary_eco,
            "host_set_key": frozenset(d["hosts"]),
        })

    print(f"  Tong repo co allowlist do duoc (eff)      : {n_total}")
    print(f"  Loai vi thuoc 12-repo noise               : {n_drop_noise}")
    print(f"  Loai vi thieu metadata repo                : {n_drop_meta_missing}")
    print(f"  Loai vi archived                           : {n_drop_archived}")
    print(f"  Loai vi push qua {WINDOW_DAYS} ngay (KHONG con log)  : {n_drop_old}")
    print(f"  Loai vi khong khop ecosystem nao biet       : {n_drop_no_eco}")
    print(f"  Con lai du dieu kien (truoc khu trung lap)  : {len(candidates)}")

    # khu trung lap allowlist y het nhau (bot tu dong), giu 1 dai dien / host_set,
    # uu tien: khong phai fork > nhieu host hon > push gan hon
    by_hostset = defaultdict(list)
    for c in candidates:
        by_hostset[c["host_set_key"]].append(c)
    deduped = []
    for hs, group in by_hostset.items():
        group.sort(key=lambda c: (c["is_fork"], -c["n_declared_hosts"], c["days_since_push"]))
        deduped.append(group[0])
    n_dup_removed = len(candidates) - len(deduped)
    print(f"  Loai trung lap allowlist y het (bot)        : {n_dup_removed} repo")
    print(f"  Con lai la MAU DOC LAP                      : {len(deduped)}")

    # uu tien khong fork, cang nhieu host cang tot (allowlist giau thong tin
    # hon cho Buoc 3), cang gan cang tot
    deduped.sort(key=lambda c: (c["is_fork"], -c["n_declared_hosts"], c["days_since_push"]))

    if run_all:
        # --all: lay het, khong can da dang/cap so luong
        selected = deduped
    else:
        # chon da dang: round-robin qua tung ecosystem bucket theo ECOSYSTEM_PRIORITY,
        # sau do lay them bat ky con thieu cho du target_n
        buckets = defaultdict(list)
        for c in deduped:
            buckets[c["primary_ecosystem"]].append(c)

        selected, seen_repo = [], set()
        round_idx = 0
        eco_order = sorted(buckets, key=lambda e: (ECOSYSTEM_PRIORITY.index(e)
                                                    if e in ECOSYSTEM_PRIORITY else 999))
        while len(selected) < target_n:
            progressed = False
            for eco in eco_order:
                if len(selected) >= target_n:
                    break
                b = buckets[eco]
                if round_idx < len(b):
                    c = b[round_idx]
                    if c["repo"] not in seen_repo:
                        selected.append(c)
                        seen_repo.add(c["repo"])
                        progressed = True
            round_idx += 1
            if not progressed:
                break

    n_target_label = len(deduped) if run_all else target_n
    print(f"\n  DA CHON {len(selected)}/{n_target_label} repo, {len(set(c['primary_ecosystem'] for c in selected))} "
          f"ecosystem khac nhau:\n")
    header = f"  {'repo':45s} {'eco':11s} {'|I|':>4s} {'lang':10s} {'ngay truoc':>10s} {'fork':>5s}"
    print(header)
    preview = selected[:30] if run_all else selected
    for c in preview:
        print(f"  {c['repo']:45s} {c['primary_ecosystem']:11s} {c['n_declared_hosts']:>4d} "
              f"{str(c['language'])[:10]:10s} {c['days_since_push']:>10d} {str(c['is_fork']):>5s}")
    if run_all and len(selected) > 30:
        print(f"  ... con {len(selected) - 30} repo nua, xem day du trong {OUT_JSON}")

    eco_hist = defaultdict(int)
    for c in selected:
        eco_hist[c["primary_ecosystem"]] += 1
    print(f"\n  Phan bo ecosystem: {dict(eco_hist)}")

    out = {
        "generated_at": now.isoformat(),
        "window_days": WINDOW_DAYS,
        "cutoff_pushed_at": cutoff.isoformat(),
        "criteria": [
            "khong thuoc 12 repo noise step-security",
            "public (gia dinh tu nguon Code Search API - CAN xac nhan lai bang "
            "`gh repo view --json isPrivate` o Buoc 1)",
            f"pushed_at trong {WINDOW_DAYS} ngay gan day (tinh tu {now.date()})",
            "co it nhat 1 ecosystem nhan dien duoc tu domain da khai bao trong I",
            "(bo sung) khong archived, uu tien khong fork, khu trung lap allowlist y het",
        ],
        "funnel": {
            "n_total_eff_repos": n_total,
            "dropped_noise": n_drop_noise,
            "dropped_meta_missing": n_drop_meta_missing,
            "dropped_archived": n_drop_archived,
            "dropped_pushed_too_old": n_drop_old,
            "dropped_no_ecosystem_match": n_drop_no_eco,
            "dropped_duplicate_allowlist": n_dup_removed,
            "n_eligible_after_all_filters": len(deduped),
        },
        "ecosystem_distribution_selected": dict(eco_hist),
        "selected": [
            {k: v for k, v in c.items() if k != "host_set_key"} for c in selected
        ],
    }
    OUT_JSON.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Da ghi {OUT_JSON}")

    if len(selected) < TARGET_N:
        print(f"\n  !! CANH BAO: chi chon duoc {len(selected)}/{TARGET_N} - noi long tieu chi "
              f"hoac giam TARGET_N truoc khi chay Buoc 1.")


if __name__ == "__main__":
    main()
