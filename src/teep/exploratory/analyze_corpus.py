#!/usr/bin/env python3
"""
analyze.py - Phan tich corpus egress allowlist, sinh bang + bieu do cho paper.

CAI DAT
    pip install pandas matplotlib

CHAY
    python analyze.py                  # chay tat ca
    python analyze.py --only dedup     # chi mot phan

DAU RA
    analysis/tables/*.md     bang Markdown (dan vao note)
    analysis/tables/*.tex    bang LaTeX (dan vao paper)
    analysis/figures/*.png   bieu do 300dpi
    analysis/summary.txt     tom tat con so

QUAN TRONG NHAT la phan DEDUP. No tra loi cau hoi ma reviewer se hoi dau tien:
"6.324 allowlist cua ban co thuc su la 6.324 policy doc lap, hay la 50 policy
duoc copy-paste 6.324 lan?" Neu la cai thu hai, N thuc te cua ban nho hon
nhieu va moi thong ke deu phai tinh lai.
"""

from teep import paths as _P
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("Thieu pandas. Chay: pip install pandas matplotlib")

HAVE_PLT = True
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    HAVE_PLT = False

DATA = _P.data("data")
OUT = _P.data("analysis")
TBL = OUT / "tables"
FIG = OUT / "figures"

# style bieu do: don gian, in den trang van doc duoc
if HAVE_PLT:
    plt.rcParams.update({
        "figure.dpi": 300, "savefig.dpi": 300, "font.size": 9,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.5,
        "figure.autolayout": True,
    })

TEMPLATE_RE = re.compile(r"\$\{\{")
_lines = []


def say(msg=""):
    print(msg)
    _lines.append(str(msg))


def load(name):
    p = DATA / name
    if not p.exists():
        return pd.DataFrame()
    rows = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return pd.DataFrame(rows)


def write_table(name, df, caption="", index=False):
    TBL.mkdir(parents=True, exist_ok=True)
    (TBL / f"{name}.md").write_text(
        (f"**{caption}**\n\n" if caption else "") + df.to_markdown(index=index),
        encoding="utf-8")
    try:
        (TBL / f"{name}.tex").write_text(
            df.to_latex(index=index, escape=True, caption=caption or name,
                        label=f"tab:{name}"), encoding="utf-8")
    except Exception:
        pass
    print(f"    -> tables/{name}.md + .tex")


def save_fig(name):
    if not HAVE_PLT:
        return
    FIG.mkdir(parents=True, exist_ok=True)
    plt.savefig(FIG / f"{name}.png", bbox_inches="tight")
    plt.close()
    print(f"    -> figures/{name}.png")


# =====================================================================
def prep(pol):
    """Chuan hoa + danh dau cac cot dan xuat."""
    if pol.empty:
        return pol
    for c in ("hosts", "endpoints", "wildcards"):
        if c not in pol.columns:
            pol[c] = [[] for _ in range(len(pol))]
        pol[c] = pol[c].apply(lambda v: v if isinstance(v, list) else [])
    # chuan hoa egress_policy MOT LAN. pandas 3.x giu NaN qua astype(str),
    # nen phai fillna truoc, neu khong regex nhan phai float -> TypeError.
    if "egress_policy" in pol.columns:
        pol["_ep"] = pol["egress_policy"].fillna("").map(
            lambda v: "" if v is None else str(v)).str.strip()
    else:
        pol["_ep"] = ""

    if "enforced" not in pol.columns:
        pol["enforced"] = pol["_ep"] == "block"
    pol["enforced"] = pol["enforced"].fillna(False).astype(bool)

    # policy dat dong (block/audit quyet dinh luc chay)
    pol["dynamic_policy"] = pol["_ep"].map(lambda v: bool(TEMPLATE_RE.search(v)))
    # allowlist dinh nghia gian tiep qua vars/inputs
    if "uses_templating" in pol.columns:
        pol["templated_list"] = pol["uses_templating"].fillna(False).astype(bool)
    else:
        pol["templated_list"] = pol["endpoints"].apply(
            lambda eps: any(TEMPLATE_RE.search(str(e)) for e in eps))

    pol["host_set"] = pol["hosts"].apply(lambda h: frozenset(x.lower() for x in h))
    pol["n_hosts"] = pol["host_set"].apply(len)
    return pol


# =====================================================================
def sec_overview(pol, repos):
    say("\n" + "=" * 68)
    say("1. TONG QUAN — CON SO O CA HAI DON VI PHAN TICH")
    say("=" * 68)
    say("Bao cao ca step-level va repo-level. % tinh tren step de bi thoi phong")
    say("vi mot repo co the co hang chuc workflow giong nhau.\n")

    n_step, n_repo = len(pol), pol["repo"].nunique()
    blk = pol[pol["enforced"]]
    eff = blk[(blk["n_hosts"] > 0) & (~blk["templated_list"])]

    rows = [
        ("Tat ca step harden-runner", n_step, n_repo),
        ("  egress-policy: audit", int((pol["_ep"] == "audit").sum()),
         pol[pol["_ep"] == "audit"]["repo"].nunique()),
        ("  egress-policy: block", len(blk), blk["repo"].nunique()),
        ("  policy dat dong (template)", int(pol["dynamic_policy"].sum()),
         pol[pol["dynamic_policy"]]["repo"].nunique()),
        ("block + allowlist do duoc", len(eff), eff["repo"].nunique()),
        ("block nhung allowlist templated", int(blk["templated_list"].sum()),
         blk[blk["templated_list"]]["repo"].nunique()),
    ]
    df = pd.DataFrame(rows, columns=["Nhom", "Step", "Repo"])
    df["% step"] = (df["Step"] / n_step * 100).round(1)
    df["% repo"] = (df["Repo"] / n_repo * 100).round(1)
    say(df.to_string(index=False))
    write_table("t1_overview", df, "Phan tang corpus theo che do egress")

    # F1 — bieu do phat hien chinh: bao nhieu % thuc su chan
    if HAVE_PLT:
        labels = ["Audit\n(chi giam sat)", "Block\n(co chan)", "Block +\nallowlist do duoc"]
        vals = [int((pol["_ep"] == "audit").sum()), len(blk), len(eff)]
        fig, ax = plt.subplots(figsize=(4.2, 2.9))
        bars = ax.bar(labels, vals, color=["#a0aec0", "#4a5568", "#2d3748"])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v}\n({100*v/n_step:.1f}%)",
                    ha="center", va="bottom", fontsize=8)
        ax.set_ylabel("So step harden-runner")
        ax.set_ylim(0, max(vals) * 1.25)
        save_fig("f1_enforcement_funnel")

    say(f"\n  -> DON VI PHAN TICH CHINH: {len(eff)} step / "
        f"{eff['repo'].nunique()} repo co allowlist do duoc.")
    say(f"  -> Trung binh {n_step/n_repo:.1f} step harden-runner moi repo. "
        f"Neu bao cao % theo step, mot repo co 50 workflow se dem 50 lan.")
    return eff


# =====================================================================
def sec_dedup(eff):
    """PHAN QUAN TRONG NHAT. Bao nhieu allowlist that su khac nhau?"""
    say("\n" + "=" * 68)
    say("2. TRUNG LAP — N THUC TE CUA BAN LA BAO NHIEU?")
    say("=" * 68)
    if eff.empty:
        say("  (khong co du lieu)")
        return None

    # 2a. trung lap chinh xac
    groups = defaultdict(list)
    for _, r in eff.iterrows():
        groups[r["host_set"]].append(r["repo"])

    n_distinct = len(groups)
    say(f"  Allowlist (step)          : {len(eff)}")
    say(f"  Tap host PHAN BIET        : {n_distinct}")
    say(f"  Ty le nen                 : {len(eff)/max(n_distinct,1):.1f}x")

    # dedup theo repo: mot repo dong gop toi da 1 lan cho moi tap host
    repo_distinct = len({(r, hs) for hs, rs in groups.items() for r in set(rs)})
    say(f"  Cap (repo, tap host) unique: {repo_distinct}")

    sizes = sorted((len(set(rs)) for rs in groups.values()), reverse=True)
    say(f"\n  Phan bo so REPO dung chung mot tap host:")
    say(f"    chi 1 repo dung        : {sum(1 for s in sizes if s == 1)} tap "
        f"({100*sum(1 for s in sizes if s==1)/max(n_distinct,1):.1f}%)")
    say(f"    2-5 repo dung          : {sum(1 for s in sizes if 2 <= s <= 5)} tap")
    say(f"    6-20 repo dung         : {sum(1 for s in sizes if 6 <= s <= 20)} tap")
    say(f"    >20 repo dung          : {sum(1 for s in sizes if s > 20)} tap")

    top = sorted(groups.items(), key=lambda kv: -len(set(kv[1])))[:10]
    rows = []
    for hs, rs in top:
        rows.append({
            "N repo": len(set(rs)),
            "N host": len(hs),
            "Host (3 dau)": ", ".join(sorted(hs)[:3]) + ("..." if len(hs) > 3 else ""),
        })
    df = pd.DataFrame(rows)
    say(f"\n  10 allowlist duoc sao chep nhieu nhat:")
    say(df.to_string(index=False))
    write_table("t2_duplicate_allowlists", df, "Allowlist duoc sao chep nhieu nhat")

    # 2b. gan trung lap (Jaccard) — dung inverted index cho nhanh
    say(f"\n  Gan trung lap (Jaccard >= 0.8), tren {n_distinct} tap phan biet:")
    keys = list(groups.keys())
    inv = defaultdict(set)
    for i, hs in enumerate(keys):
        for h in hs:
            inv[h].add(i)
    parent = list(range(len(keys)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i, hs in enumerate(keys):
        cand = set()
        for h in hs:
            if len(inv[h]) < 500:          # bo host cuc pho bien cho nhanh
                cand |= inv[h]
        for j in cand:
            if j <= i:
                continue
            other = keys[j]
            inter = len(hs & other)
            if inter == 0:
                continue
            if inter / len(hs | other) >= 0.8:
                union(i, j)

    clusters = Counter(find(i) for i in range(len(keys)))
    say(f"    Cum sau khi gop        : {len(clusters)}")
    say(f"    Cum lon nhat           : {max(clusters.values())} tap")
    say(f"\n  -> N HIEU DUNG cho thong ke: khoang {len(clusters)}, "
        f"khong phai {len(eff)}.")
    say(f"  -> Bao cao ca hai con so trong paper. Neu chi bao cao {len(eff)},")
    say(f"     reviewer se hoi ngay va ban mat uy tin.")

    if HAVE_PLT and sizes:
        plt.figure(figsize=(4.2, 2.8))
        plt.hist(sizes, bins=min(50, max(sizes)), color="#4a5568")
        plt.yscale("log")
        plt.xlabel("So repo dung chung mot tap host")
        plt.ylabel("So tap host (log)")
        save_fig("f2_duplication")
    return len(clusters)


# =====================================================================
def sec_size(eff):
    say("\n" + "=" * 68)
    say("3. KICH THUOC ALLOWLIST — TAP DINH CHO PHEP")
    say("=" * 68)
    if eff.empty:
        return
    n = eff["n_hosts"]
    q = n.quantile([.25, .5, .75, .9, .95, .99])
    say(f"  min={n.min()}  p25={q[.25]:.0f}  median={q[.5]:.0f}  p75={q[.75]:.0f}  "
        f"p90={q[.9]:.0f}  p95={q[.95]:.0f}  p99={q[.99]:.0f}  max={n.max()}")
    say(f"  trung binh={n.mean():.1f}  (lech phai manh: mean >> median)")
    say(f"\n  -> Median {q[.5]:.0f} host la con so quan trong: tap DINH cho phep")
    say(f"     rat nho. Moi don vi noi rong deu de thay.")

    df = pd.DataFrame({
        "Thong ke": ["min", "p25", "median", "p75", "p90", "p99", "max", "mean"],
        "So host": [n.min(), q[.25], q[.5], q[.75], q[.9], q[.99], n.max(),
                    round(n.mean(), 1)],
    })
    write_table("t3_allowlist_size", df, "Phan bo kich thuoc allowlist")

    if HAVE_PLT:
        plt.figure(figsize=(4.2, 2.8))
        plt.hist(n.clip(upper=60), bins=60, color="#4a5568")
        plt.yscale("log")
        plt.xlabel("So host trong allowlist (cat o 60)")
        plt.ylabel("So allowlist (log)")
        save_fig("f3_allowlist_size")


# =====================================================================
def sec_hosts(eff):
    say("\n" + "=" * 68)
    say("4. HOST — DAU VAO CHO PHAN TICH CO-TENANCY")
    say("=" * 68)
    if eff.empty:
        return
    cnt = Counter()
    for hs in eff["host_set"]:
        cnt.update(hs)
    say(f"  Host unique: {len(cnt)}")

    tot = sum(cnt.values())
    cum, k50, k90 = 0, None, None
    for i, (_, c) in enumerate(cnt.most_common(), 1):
        cum += c
        if k50 is None and cum >= tot * .5:
            k50 = i
        if k90 is None and cum >= tot * .9:
            k90 = i
            break
    say(f"  {k50} host dau chiem 50% tong luot xuat hien")
    say(f"  {k90} host dau chiem 90%")
    say(f"  -> Chi can resolve ~{k90} host la phu 90% corpus. Kha thi.")

    rows = [{"Host": h, "N allowlist": c,
             "% allowlist": round(100 * c / len(eff), 1)}
            for h, c in cnt.most_common(40)]
    df = pd.DataFrame(rows)
    write_table("t4_top_hosts", df, "Host xuat hien nhieu nhat trong allowlist")
    say(f"\n  Top 15:")
    say(df.head(15).to_string(index=False))

    # host tu khai la nhan du lieu — tin hieu co hoc, khong phan xet
    SINK = re.compile(r"^(uploads?|hooks?|webhooks?|ingest|storage|blob|files?|"
                      r"artifacts?|s3|r2)\.|\.(s3|r2|blob)\.", re.I)
    sink_hosts = {h: c for h, c in cnt.items() if SINK.search(h)}
    n_pol = sum(1 for hs in eff["host_set"] if any(SINK.search(h) for h in hs))
    say(f"\n  Host co tien to bao hieu 'nhan du lieu' (upload/hooks/storage/...):")
    say(f"    {len(sink_hosts)} host unique, xuat hien trong {n_pol} allowlist "
        f"({100*n_pol/len(eff):.1f}%)")
    for h, c in sorted(sink_hosts.items(), key=lambda x: -x[1])[:12]:
        say(f"      {c:6d}  {h}")
    say(f"  -> Day la QUY TAC CU PHAP, chua phai ket luan. Phai hand-label 100 mau")
    say(f"     de bao cao precision truoc khi dua con so nay vao paper.")

    # loc truoc khi feed vao dns_cotenancy: IP tran va SRV record khong resolve
    # duoc bang A record, chung se sinh NXDOMAIN gia.
    IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    SRV = re.compile(r"^_[a-z0-9-]+\._(tcp|udp)\.", re.I)
    HOSTLIKE = re.compile(r"^[a-z0-9*][a-z0-9.*_-]*\.[a-z]{2,}$", re.I)

    resolvable, ip_lits, srv, odd = [], [], [], []
    for h, _ in cnt.most_common():
        if IPV4.match(h):
            ip_lits.append(h)
        elif SRV.match(h):
            srv.append(h)
        elif "*" in h or not HOSTLIKE.match(h):
            odd.append(h)
        else:
            resolvable.append(h)

    (OUT / "hosts_for_resolution.txt").write_text(
        "\n".join(resolvable), encoding="utf-8")
    (OUT / "hosts_ip_literals.txt").write_text("\n".join(ip_lits), encoding="utf-8")
    say(f"\n  Loc truoc khi resolve:")
    say(f"    resolve duoc          : {len(resolvable)} (ghi 400 dau ra file)")
    say(f"    IP tran trong allowlist: {len(ip_lits)}  {ip_lits[:6]}")
    say(f"    SRV record            : {len(srv)}  {srv[:3]}")
    say(f"    wildcard / khac       : {len(odd)}  {odd[:3]}")
    if ip_lits:
        say(f"  -> IP tran la mot phat hien nho: policy tron IP va domain trong")
        say(f"     cung mot allowlist. Xu ly rieng bang tra CIDR, khong resolve.")
    print(f"    -> analysis/hosts_for_resolution.txt ({len(resolvable)} host)")

    if HAVE_PLT:
        top = cnt.most_common(20)[::-1]
        plt.figure(figsize=(4.6, 4.4))
        plt.barh([h for h, _ in top], [c for _, c in top], color="#4a5568")
        plt.xlabel("So allowlist chua host nay")
        save_fig("f4_top_hosts")


# =====================================================================
def sec_wildcard(eff):
    say("\n" + "=" * 68)
    say("5. WILDCARD — NOI RONG THUAN CU PHAP")
    say("=" * 68)
    if eff.empty:
        return
    has = eff["wildcards"].apply(lambda w: len(w) > 0)
    say(f"  Allowlist co >=1 wildcard: {int(has.sum())} ({100*has.mean():.1f}%)")
    cnt = Counter()
    for w in eff["wildcards"]:
        cnt.update(x.lower() for x in w)
    rows = [{"Pattern": p, "N": c} for p, c in cnt.most_common(20)]
    if rows:
        df = pd.DataFrame(rows)
        say(df.to_string(index=False))
        write_table("t5_wildcards", df, "Wildcard pattern pho bien")
    say(f"\n  -> Voi moi pattern, so subdomain that su khop la mot con so dem duoc")
    say(f"     qua Certificate Transparency log. Do la 'do noi rong' cua lop nay.")


# =====================================================================
def sec_version(pol):
    say("\n" + "=" * 68)
    say("6. VERSION & TIER")
    say("=" * 68)
    if pol.empty or "version_semver" not in pol.columns:
        return

    def parse_v(v):
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(v).strip())
        return tuple(int(x) for x in m.groups()) if m else None

    pol["_v"] = pol["version_semver"].apply(parse_v)
    known = pol[pol["_v"].notna()]
    say(f"  Step co version day du: {len(known)}/{len(pol)} "
        f"({100*len(known)/len(pol):.1f}%)")
    if len(known):
        old = known["_v"] < (2, 16, 0)
        say(f"  < v2.16.0 (chua va DoH bypass GHSA-46g3-37rh-v698): "
            f"{int(old.sum())} ({100*old.mean():.1f}%)")
        old_repo = known[old]["repo"].nunique()
        say(f"    theo repo: {old_repo}/{known['repo'].nunique()} "
            f"({100*old_repo/known['repo'].nunique():.1f}%)")
    pin = pol["version_pin"].value_counts()
    say(f"\n  Kieu pin: {dict(pin)}")
    say(f"    SHA pinning {100*pin.get('sha',0)/len(pol):.1f}% — cao, tot cho supply")
    say(f"    chain nhung KEM cho va loi: pin SHA khong tu nhan ban va.")
    # tuong quan: pin SHA co lam cham va khong?
    if len(known) and "version_pin" in known.columns:
        ct = pd.crosstab(known["version_pin"], known["_v"] < (2, 16, 0))
        ct.columns = ["Da va (>=2.16.0)", "Chua va (<2.16.0)"][:len(ct.columns)]
        ct["% chua va"] = (ct.iloc[:, -1] / ct.sum(axis=1) * 100).round(1)
        say(f"\n  Pin SHA co lam cham nhan ban va khong?")
        say(ct.to_string())
        write_table("t6_pin_vs_patch", ct.reset_index(),
                    "Kieu pin version doi chieu voi tinh trang va DoH bypass")
        say(f"  -> Neu ty le 'chua va' cao hon o nhom SHA: pin SHA (best practice")
        say(f"     supply chain) lam cham viec nhan ban va. Do la mot tension that")
        say(f"     giua hai nguyen tac bao mat, dang mot doan Discussion.")

    if HAVE_PLT and len(known):
        vc = known["version_semver"].value_counts().head(12).sort_index()
        colors = ["#c05621" if parse_v(v) and parse_v(v) < (2, 16, 0) else "#4a5568"
                  for v in vc.index]
        plt.figure(figsize=(4.6, 2.9))
        plt.bar(range(len(vc)), vc.values, color=colors)
        plt.xticks(range(len(vc)), vc.index, rotation=60, ha="right", fontsize=7)
        plt.ylabel("So step")
        plt.title("Cam = truoc v2.16.0 (chua va DoH bypass)", fontsize=8)
        save_fig("f6_version")

    tier = pol["tier_signal"].value_counts()
    say(f"\n  Tier: {dict(tier)}")
    say(f"  -> Gan nhu toan bo corpus la Community Tier — dung tier BI anh huong")
    say(f"     boi DoH bypass. Khong phai lo tron lan hai population.")


# =====================================================================
def sec_repos(pol, repos, eff):
    say("\n" + "=" * 68)
    say("7. DAC DIEM REPO — RUI RO DAI DIEN")
    say("=" * 68)
    if repos.empty:
        say("  (thieu repos_ci.jsonl)")
        return
    r = repos[repos.get("status") == "ok"].copy()
    if r.empty:
        return
    eff_repos = set(eff["repo"]) if not eff.empty else set()
    r["in_eff"] = r["repo"].isin(eff_repos)

    for label, sub in [("Toan corpus", r), ("Chi repo co allowlist", r[r["in_eff"]])]:
        if sub.empty:
            continue
        st = sub["stars"].fillna(0)
        say(f"\n  {label} (n={len(sub)}):")
        say(f"    stars: median={st.median():.0f} p75={st.quantile(.75):.0f} "
            f"p90={st.quantile(.9):.0f} max={st.max():.0f}")
        say(f"    stars = 0 hoac 1: {int((st <= 1).sum())} "
            f"({100*(st<=1).mean():.1f}%)")
        if "is_fork" in sub.columns:
            f = sub["is_fork"].fillna(False)
            say(f"    fork: {int(f.sum())} ({100*f.mean():.1f}%)")
        if "owner_type" in sub.columns:
            say(f"    owner: {dict(sub['owner_type'].value_counts())}")

    st = r["stars"].fillna(0)
    say(f"\n  ! CANH BAO DAI DIEN: median stars = {st.median():.0f}.")
    say(f"    Corpus bi chi phoi boi repo rat it sao. Nhieu kha nang do")
    say(f"    OpenSSF Scorecard / bot mo PR tu dong them harden-runner.")
    say(f"    -> BAT BUOC phan tang theo stars khi bao cao ket qua chinh.")
    say(f"    -> Kiem tra: allowlist cua repo >100 sao co khac repo 0 sao khong?")

    if not eff.empty:
        m = eff.merge(r[["repo", "stars"]], on="repo", how="left")
        m["stars"] = m["stars"].fillna(0)
        bins = [(0, 1, "0-1"), (2, 10, "2-10"), (11, 100, "11-100"),
                (101, 10**9, ">100")]
        rows = []
        for lo, hi, lab in bins:
            s = m[(m["stars"] >= lo) & (m["stars"] <= hi)]
            if len(s):
                rows.append({"Nhom sao": lab, "N allowlist": len(s),
                             "Median size": int(s["n_hosts"].median()),
                             "% co wildcard": round(
                                 100 * s["wildcards"].apply(
                                     lambda w: len(w) > 0).mean(), 1)})
        if rows:
            df = pd.DataFrame(rows)
            say(f"\n  Allowlist theo nhom sao:")
            say(df.to_string(index=False))
            write_table("t7_by_stars", df, "Dac diem allowlist theo do pho bien repo")

    if "created_at" in r.columns and HAVE_PLT:
        d = pd.to_datetime(r["created_at"], errors="coerce", utc=True).dropna()
        if len(d) > 20:
            plt.figure(figsize=(4.6, 2.6))
            d.dt.to_period("M").value_counts().sort_index().plot(
                kind="line", color="#4a5568")
            plt.xlabel("Thang tao repo")
            plt.ylabel("So repo")
            save_fig("f7_repo_created")


# =====================================================================
def sec_next(eff, n_eff):
    say("\n" + "=" * 68)
    say("8. VIEC TIEP THEO")
    say("=" * 68)
    say("""
  A. HAND-LABEL 100 ENDPOINT (1 buoi, khong bo qua duoc)
     Lay ngau nhien 100 host tu hosts_for_resolution.txt, tu tay xac dinh:
     co nhan noi dung nguoi dung khong? Bao cao precision/recall cua quy tac
     cu phap. Thieu buoc nay thi moi con so phan loai deu bi bac.

  B. CO-TENANCY VOI TRANCO (con so chinh cua bai)
     Tai Tranco top 1M (tranco-list.eu). Resolve top 100k.
     Xay index IP -> domain. Voi moi host trong allowlist, dem xem IP cua no
     con phuc vu bao nhieu domain khac. Do la 'do noi rong' cua co che L3/L4.

  C. WILDCARD EXPANSION QUA CT LOG
     crt.sh cho phep query subdomain theo pattern. Voi moi wildcard, dem so
     subdomain that su ton tai. Do la 'do noi rong' cua lop wildcard.

  D. KIEM TRA THIEN LECH BOT
     Repo median 1 sao rat dang ngo. Lay 30 repo 0-1 sao, xem lich su commit:
     allowlist do nguoi viet hay bot them? Neu phan lon la bot, phai noi ro
     trong Limitations va co the phai gioi han corpus.
""")
    if n_eff:
        say(f"  Nho: moi thong ke chinh bao cao kem N hieu dung ~{n_eff}, "
            f"khong chi N tho.")


# =====================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="overview|dedup|size|hosts|wildcard|version|repos")
    a = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    pol = prep(load("policies_ci.jsonl"))
    repos = load("repos_ci.jsonl")
    if pol.empty:
        sys.exit("Khong co data/policies_ci.jsonl. Chay parse truoc.")

    print(f"Doc {len(pol)} policy record, {len(repos)} repo\n")
    eff = pol[pol["enforced"] & (pol["n_hosts"] > 0) & (~pol["templated_list"])]

    run = a.only
    n_eff = None
    if not run or run == "overview":
        eff = sec_overview(pol, repos)
    if not run or run == "dedup":
        n_eff = sec_dedup(eff)
    if not run or run == "size":
        sec_size(eff)
    if not run or run == "hosts":
        sec_hosts(eff)
    if not run or run == "wildcard":
        sec_wildcard(eff)
    if not run or run == "version":
        sec_version(pol)
    if not run or run == "repos":
        sec_repos(pol, repos, eff)
    if not run:
        sec_next(eff, n_eff)

    (OUT / "summary.txt").write_text("\n".join(_lines), encoding="utf-8")
    print(f"\n>>> analysis/summary.txt | tables/ | figures/")


if __name__ == "__main__":
    main()
