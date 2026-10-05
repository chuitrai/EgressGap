#!/usr/bin/env python3
"""
hr_crawl.py - Egress allowlist corpus collector.

Thu thap corpus policy egress tu GitHub cho measurement study
"residual exfiltration capacity of real-world egress allowlists".

CAI DAT
    pip install requests pyyaml
    export GITHUB_TOKEN=ghp_xxxx        # PAT, chi can scope 'public_repo'

QUY TRINH 4 BUOC (chay tuan tu)
    python hr_crawl.py discover --corpus ci      # -> data/candidates.jsonl
    python hr_crawl.py fetch    --corpus ci      # -> data/files/*.yml + files.jsonl
    python hr_crawl.py parse    --corpus ci      # -> data/policies.jsonl
    python hr_crawl.py stats                     # -> con so de bao cao

CHAY LAI AN TOAN: moi buoc deu resumable. Ctrl-C bat cu luc nao roi chay lai
cung lenh, no se bo qua nhung gi da lam.

GIOI HAN DA XU LY
  - Code search API tra ve toi da 1000 ket qua/query  -> chia nho theo size: de quy
  - Code search API: 10 request/phut                  -> rate limiter tu dong
  - Core API: 5000 request/gio                        -> rate limiter tu dong
  - Secondary rate limit (403 dot ngot)               -> exponential backoff
  - Noi dung file lay qua raw.githubusercontent.com   -> KHONG ton quota API
"""

from teep import paths as _P
import argparse
import hashlib
import json
import os
import pathlib
import random
import re
import sys


import time
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

try:
    import requests
    import yaml
except ImportError:
    sys.exit("Thieu dependency. Chay: pip install requests pyyaml")

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
DATA = _P.data("data")
UA = "egress-allowlist-research/0.1 (academic measurement study)"


# ---------------------------------------------------------------- .env

def load_dotenv_simple(max_up=5):
    """Tu doc file .env (KEY=VALUE moi dong, bo qua dong '#' va dong rong),
    nap vao os.environ - KHONG can cai them python-dotenv (tranh phai them
    dependency moi + lo "pip install requests pyyaml" o dau file khong con
    dung nua).

    Bien MOI TRUONG THAT (da export san) LUON duoc uu tien - chi dien vao
    o con thieu, khong ghi de - dung quy uoc chuan cua moi thu vien dotenv.

    Tim .env bat dau tu THU MUC LAM VIEC HIEN TAI (os.getcwd(), khop dung
    quy uoc DATA = Path("data") cua file nay - CHINH DATA cung tinh theo
    CWD chu khong theo vi tri file .py), roi di LEN toi da `max_up` thu muc
    cha - de du chay lenh dung o thu muc goc project (co san .env) hay dung
    trong pipeline/ (khong co .env, phai tim len 1 cap) van tim ra dung file.

    Ly do bug thuc te dan den ham nay: `uv run` KHONG tu dong nap .env (tru
    khi goi `uv run --env-file .env`, ban uv co the khong ho tro), va ban
    than script nay truoc day khong doc .env o dau ca - nen du .env dung
    dinh dang, dung noi dung van khong co tac dung gi (da xac nhan qua doc
    code + Bao tu thu 3 cach dat .env deu khong an thua)."""
    d = Path.cwd()
    for _ in range(max_up + 1):
        f = d / ".env"
        if f.exists():
            n_loaded = 0
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip()
                if v and v[0] == v[-1] and v[0] in ("'", '"'):
                    v = v[1:-1]
                if k and k not in os.environ:
                    os.environ[k] = v
                    n_loaded += 1
            log(f"[.env] doc {f} ({n_loaded} bien moi nap - bien da export san "
                f"tu truoc KHONG bi ghi de)")
            return f
        if d.parent == d:
            break
        d = d.parent
    log("[.env] khong tim thay file .env (tu thu muc lam viec hien tai di len "
        f"{max_up} cap) - neu can GITHUB_TOKEN, dat bang export hoac tao .env.")
    return None


# ---------------------------------------------------------------- queries

# Moi query la mot "seed" doc lap. Union cua chung = candidate set.
# Ly do dung nhieu seed: code search index khong day du, mot seed se miss.
QUERIES = {
    "ci": [
        ('"step-security/harden-runner" path:.github/workflows', "uses"),
        ('"egress-policy" path:.github/workflows', "egress_kw"),
        ('"allowed-endpoints" path:.github/workflows', "allowlist_kw"),
        ('"use-policy-store" path:.github/workflows', "policy_store"),
        ('"harden-runner" path:.github/workflows', "loose"),
    ],
    "k8s": [
        ('"toFQDNs" extension:yaml', "cilium_fqdn"),
        ('"CiliumNetworkPolicy" extension:yaml', "cilium_cnp"),
        ('"kind: NetworkPolicy" "egress" extension:yaml', "k8s_netpol"),
        ('"toCIDR" extension:yaml', "cilium_cidr"),
        ('"ipBlock" "egress" extension:yaml', "netpol_ipblock"),
    ],
}

WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$", re.I)
HR_USES_RE = re.compile(r"^step-security/harden-runner@(.+)$")
SEMVER_COMMENT_RE = re.compile(r"#\s*v?(\d+\.\d+\.\d+)")


# ---------------------------------------------------------------- http layer

class GH:
    """GitHub client voi rate limiting + retry."""

    def __init__(self, token):
        self.s = requests.Session()
        self.s.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": UA,
        })
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        self.search_calls = []   # timestamps, de tu gioi han 10/phut
        self.core_used = 0

    def _throttle_search(self):
        """Code search API: 10 req/phut. Tu giu nhip, dung de bi 403."""
        now = time.time()
        self.search_calls = [t for t in self.search_calls if now - t < 60]
        if len(self.search_calls) >= 9:
            wait = 60 - (now - self.search_calls[0]) + 1
            log(f"  [rate] cho {wait:.0f}s (code search 10/phut)")
            time.sleep(max(wait, 1))
            self.search_calls = []
        self.search_calls.append(time.time())

    def get(self, url, params=None, is_search=False, tries=5):
        for attempt in range(tries):
            if is_search:
                self._throttle_search()
            try:
                r = self.s.get(url, params=params, timeout=45)
            except requests.RequestException as e:
                sleep = 2 ** attempt + random.random()
                log(f"  [net] {type(e).__name__}, retry sau {sleep:.1f}s")
                time.sleep(sleep)
                continue

            if not is_search:
                self.core_used += 1

            if r.status_code == 200:
                return r

            # het quota chinh
            if r.status_code in (403, 429):
                remaining = r.headers.get("x-ratelimit-remaining")
                retry_after = r.headers.get("retry-after")
                if retry_after:
                    sleep = int(retry_after) + 2
                    log(f"  [rate] secondary limit, cho {sleep}s")
                elif remaining == "0":
                    reset = int(r.headers.get("x-ratelimit-reset", time.time() + 60))
                    sleep = max(reset - time.time() + 5, 5)
                    log(f"  [rate] het quota, cho {sleep/60:.1f} phut")
                else:
                    sleep = 2 ** attempt * 5 + random.random()
                    log(f"  [rate] 403 khong ro, backoff {sleep:.0f}s")
                time.sleep(sleep)
                continue

            # 422 = vuot cua so 1000 ket qua -> caller tu xu ly
            if r.status_code == 422:
                return None
            if r.status_code in (404, 451):
                return None

            log(f"  [http] {r.status_code} {url} -> {r.text[:160]}")
            time.sleep(2 ** attempt)
        return None


def log(msg):
    print(msg, flush=True)


def jsonl_append(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def jsonl_read(path):
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


# ---------------------------------------------------------------- discover

def probe_count(gh, q):
    """Lay total_count cua mot query, khong keo ket qua."""
    r = gh.get(f"{API}/search/code", params={"q": q, "per_page": 1}, is_search=True)
    if r is None:
        return None
    return r.json().get("total_count", 0)


def harvest(gh, q, on_item):
    """Keo toi da 1000 ket qua cua mot query."""
    got = 0
    for page in range(1, 11):
        r = gh.get(f"{API}/search/code",
                   params={"q": q, "per_page": 100, "page": page},
                   is_search=True)
        if r is None:
            break
        items = r.json().get("items", [])
        if not items:
            break
        for it in items:
            on_item(it)
        got += len(items)
        if len(items) < 100:
            break
    return got


def split_by_size(gh, base_q, lo, hi, on_item, depth=0, budget=None):
    """
    Chia de quy theo file size de moi nhanh < 1000 ket qua.
    Day la cach duy nhat vuot gioi han 1000 cua code search API.
    """
    rng = f"size:{lo}..{hi}" if hi is not None else f"size:>={lo}"
    q = f"{base_q} {rng}"
    total = probe_count(gh, q)

    if total is None:
        log(f"  {'  '*depth}! {rng} -> query loi, bo qua")
        return 0
    if total == 0:
        return 0

    if total > 1000 and depth < 14 and hi is not None and hi - lo > 1:
        mid = lo + (hi - lo) // 2
        log(f"  {'  '*depth}~ {rng} = {total} > 1000, chia doi")
        n = split_by_size(gh, base_q, lo, mid, on_item, depth + 1)
        n += split_by_size(gh, base_q, mid + 1, hi, on_item, depth + 1)
        return n

    if total > 1000:
        log(f"  {'  '*depth}! {rng} = {total}, khong chia duoc nua -> mat "
            f"~{total-1000} ket qua (ghi vao truncated.log)")
        jsonl_append(DATA / "truncated.log",
                     {"query": q, "total": total, "capped_at": 1000})

    n = harvest(gh, q, on_item)
    log(f"  {'  '*depth}+ {rng} = {total} -> keo {n}")
    return n


def cmd_discover(args):
    gh = GH(os.environ.get("GITHUB_TOKEN"))
    if "Authorization" not in gh.s.headers:
        sys.exit("Can GITHUB_TOKEN. Code search API khong cho anonymous.")

    out = DATA / f"candidates_{args.corpus}.jsonl"
    seen = {(c["repo"], c["path"]) for c in jsonl_read(out)}
    log(f"Da co {len(seen)} candidate tu lan chay truoc")

    new = [0]

    def on_item(it):
        key = (it["repository"]["full_name"], it["path"])
        if key in seen:
            return
        seen.add(key)
        new[0] += 1
        jsonl_append(out, {
            "repo": key[0],
            "path": key[1],
            "html_url": it.get("html_url"),
            "corpus": args.corpus,
            "found_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    queries = QUERIES[args.corpus]
    if args.extra_query:
        queries = queries + [(args.extra_query, "custom")]

    for base_q, tag in queries:
        log(f"\n=== seed [{tag}]: {base_q}")
        total = probe_count(gh, base_q)
        log(f"  total_count toan cuc = {total}")
        if total is None:
            continue
        if total <= 1000:
            harvest(gh, base_q, on_item)
        else:
            # 0..384000 vi code search chi index file < 384 KB
            split_by_size(gh, base_q, 0, 384000, on_item)

    repos = {c["repo"] for c in jsonl_read(out)}
    log(f"\n>>> {len(seen)} (repo,path) unique | {len(repos)} repo unique "
        f"| +{new[0]} moi lan nay")
    log(f">>> {out}")

    
# ---------------------------------------------------------------- fetch

# Ky tu Windows cam trong ten file: < > : " / \\ | ? *  va control chars
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_MAX_NAME = 120   # Windows MAX_PATH = 260; chua cho prefix thu muc


def safe_name(repo, path):
    """Ten blob an toan. Ten NGAN giu nguyen nhu truoc -> tuong thich nguoc."""
    raw = f"{repo.replace('/', '__')}__{path.replace('/', '__')}"
    raw = _BAD_CHARS.sub("_", raw)
    raw = raw.rstrip(" .")          # Windows khong cho ten ket thuc bang . hoac space
    if len(raw) <= _MAX_NAME:
        return raw
    # Qua dai -> giu 80 ky tu dau cho de nhan biet, noi them hash on dinh
    h = hashlib.sha1(f"{repo}:{path}".encode("utf-8")).hexdigest()[:16]
    suffix = pathlib.PurePosixPath(path).suffix[:8]
    return f"{raw[:80]}__{h}{suffix}"


def cmd_fetch(args):
    gh = GH(os.environ.get("GITHUB_TOKEN"))
    cand = DATA / f"candidates_{args.corpus}.jsonl"
    if not cand.exists():
        sys.exit(f"Chua co {cand}. Chay 'discover' truoc.")

    files_idx = DATA / f"files_{args.corpus}.jsonl"
    blobs = DATA / "files"
    blobs.mkdir(parents=True, exist_ok=True)

    done_repos = {r["repo"] for r in jsonl_read(DATA / f"repos_{args.corpus}.jsonl")}
    have_files = {f["key"] for f in jsonl_read(files_idx)}

    by_repo = defaultdict(set)
    for c in jsonl_read(cand):
        by_repo[c["repo"]].add(c["path"])

    todo = [r for r in by_repo if r not in done_repos]
    if args.limit:
        todo = todo[:args.limit]
    log(f"{len(by_repo)} repo tong, {len(done_repos)} da xong, xu ly {len(todo)}")

    for i, repo in enumerate(todo, 1):
        owner, name = repo.split("/", 1)

        meta_r = gh.get(f"{API}/repos/{owner}/{name}")
        if meta_r is None:
            jsonl_append(DATA / f"repos_{args.corpus}.jsonl",
                         {"repo": repo, "status": "gone"})
            continue
        m = meta_r.json()
        ref = m.get("default_branch") or "HEAD"

        # Mo rong: lay TOAN BO workflow cua repo, khong chi file ma search tim ra.
        # Day la cho corpus phinh ra that su - mot repo thuong co 5-30 workflow.
        paths = set(by_repo[repo])
        if args.corpus == "ci" and not args.no_expand:
            tr = gh.get(f"{API}/repos/{owner}/{name}/git/trees/{ref}",
                        params={"recursive": "1"})
            if tr is not None:
                tj = tr.json()
                for node in tj.get("tree", []):
                    if node.get("type") == "blob" and WORKFLOW_RE.match(node["path"]):
                        paths.add(node["path"])
                if tj.get("truncated"):
                    log(f"  [{i}] {repo}: tree truncated, co the thieu file")

        _repo_rec = {
            "repo": repo,
            "status": "ok",
            "stars": m.get("stargazers_count"),
            "forks": m.get("forks_count"),
            "pushed_at": m.get("pushed_at"),
            "created_at": m.get("created_at"),
            "size_kb": m.get("size"),
            "language": m.get("language"),
            "archived": m.get("archived"),
            "is_fork": m.get("fork"),
            "owner_type": m.get("owner", {}).get("type"),
            "license": (m.get("license") or {}).get("spdx_id"),
            "default_branch": ref,
            "n_paths": len(paths),
        }

        # noi dung lay qua raw.* -> KHONG ton quota API
        for p in sorted(paths):
            key = f"{repo}:{p}"
            if key in have_files:
                continue
            url = f"{RAW}/{owner}/{name}/{ref}/{p}"
            try:
                rr = requests.get(url, timeout=30, headers={"User-Agent": UA})
            except requests.RequestException:
                continue
            if rr.status_code != 200:
                continue
            fn = safe_name(repo, p)
            try:
                (blobs / fn).write_text(rr.text, encoding="utf-8",
                                        errors="replace")
            except OSError as e:
                # Duong dan qua dai, ky tu la, dia day... -> bo qua 1 file,
                # KHONG giet ca run. Ghi log de bao cao trong Limitations.
                jsonl_append(DATA / "fetch_errors.log", {
                    "key": key, "blob": fn,
                    "error": f"{type(e).__name__}: {e}"[:300],
                })
                continue
            have_files.add(key)
            jsonl_append(files_idx, {
                "key": key, "repo": repo, "path": p,
                "blob": fn, "bytes": len(rr.content),
            })

        # ghi checkpoint SAU khi tai xong file -> Ctrl+C giua chung thi
        # lan sau lam lai ca repo, khong mat file
        jsonl_append(DATA / f"repos_{args.corpus}.jsonl", _repo_rec)

        if i % 25 == 0:
            log(f"  [{i}/{len(todo)}] {repo} | core API da dung {gh.core_used}")

    log(f"\n>>> {len(have_files)} file trong {blobs}/")


# ---------------------------------------------------------------- parse

def norm_endpoints(raw):
    """allowed-endpoints la block scalar, tach theo whitespace/comma."""
    if raw is None:
        return []
    if isinstance(raw, list):
        parts = raw
    else:
        parts = re.split(r"[\s,]+", str(raw))
    out = []
    for p in parts:
        p = p.strip().strip('"').strip("'")
        if not p or p.startswith("#"):
            continue
        out.append(p)
    return out


def split_hostport(ep):
    if ":" in ep:
        h, _, port = ep.rpartition(":")
        return (h, port) if port.isdigit() else (ep, None)
    return ep, None


def parse_hr_step(step, ctx):
    """Trich mot step harden-runner thanh mot policy record."""
    uses = str(step.get("uses", ""))
    mm = HR_USES_RE.match(uses.strip())
    if not mm:
        return None
    ver_ref = mm.group(1).strip()

    w = step.get("with") or {}
    if not isinstance(w, dict):
        w = {}

    policy = str(w.get("egress-policy", "")).strip().lower() or None
    eps = norm_endpoints(w.get("allowed-endpoints"))
    hosts = [split_hostport(e)[0] for e in eps]
    wildcards = [h for h in hosts if "*" in h]

    # tier_signal: api-key / use-policy-store => Enterprise tier
    has_key = any(k in w for k in ("api-key", "api_key"))
    uses_store = str(w.get("use-policy-store", "")).lower() in ("true", "1", "yes")
    tier = "enterprise" if (has_key or uses_store) else "unknown"

    # version: tag hay SHA? neu SHA thi tim comment semver ben canh
    is_sha = bool(re.fullmatch(r"[0-9a-f]{40}", ver_ref))
    ver_comment = None
    if is_sha:
        cm = SEMVER_COMMENT_RE.search(ctx.get("step_text", ""))
        if cm:
            ver_comment = cm.group(1)
    # chuan hoa: bo tien to 'v' de so sanh version hoat dong
    semver = ver_comment or (None if is_sha else ver_ref)
    if semver:
        semver = semver.lstrip("vV")

    return {
        **ctx["ident"],
        "source": "harden_runner",
        "enforcement_type": "dns_sni_intercept",
        "egress_policy": policy,
        "enforced": policy == "block",
        "n_endpoints": len(eps),
        "endpoints": eps,
        "hosts": sorted(set(hosts)),
        "n_unique_hosts": len(set(hosts)),
        "n_wildcards": len(wildcards),
        "wildcards": sorted(set(wildcards)),
        "version_ref": ver_ref,
        "version_pin": "sha" if is_sha else "tag",
        "version_semver": semver,
        "tier_signal": tier,
        "use_policy_store": uses_store,
        "disable_sudo": w.get("disable-sudo"),
        "disable_telemetry": w.get("disable-telemetry"),
    }


def parse_k8s_doc(doc, ctx):
    """Trich policy egress tu NetworkPolicy / CiliumNetworkPolicy."""
    if not isinstance(doc, dict):
        return None
    kind = str(doc.get("kind", ""))
    if kind not in ("NetworkPolicy", "CiliumNetworkPolicy",
                    "CiliumClusterwideNetworkPolicy"):
        return None
    spec = doc.get("spec") or {}
    if not isinstance(spec, dict):
        return None

    egress = spec.get("egress") or []
    if not isinstance(egress, list):
        egress = []

    fqdns, cidrs, ports = [], [], []
    for rule in egress:
        if not isinstance(rule, dict):
            continue
        for f in (rule.get("toFQDNs") or []):
            if isinstance(f, dict):
                v = f.get("matchName") or f.get("matchPattern")
                if v:
                    fqdns.append(str(v))
        for c in (rule.get("toCIDR") or []) + (rule.get("toCIDRSet") or []):
            cidrs.append(str(c.get("cidr") if isinstance(c, dict) else c))
        for t in (rule.get("to") or []):
            if isinstance(t, dict) and "ipBlock" in t:
                ib = t["ipBlock"] or {}
                cidrs.append(str(ib.get("cidr")))
        for p in (rule.get("ports") or rule.get("toPorts") or []):
            ports.append(str(p))

    if kind == "NetworkPolicy":
        enf = "l3l4_ip"
    else:
        enf = "identity_fqdn" if fqdns else "l3l4_ip"

    wildcards = [f for f in fqdns if "*" in f]
    return {
        **ctx["ident"],
        "source": "cilium_cnp" if kind != "NetworkPolicy" else "k8s_netpol",
        "kind": kind,
        "enforcement_type": enf,
        "policy_types": spec.get("policyTypes"),
        "n_egress_rules": len(egress),
        "fqdns": fqdns,
        "n_fqdns": len(fqdns),
        "n_wildcards": len(wildcards),
        "wildcards": wildcards,
        "cidrs": [c for c in cidrs if c and c != "None"],
        "n_cidrs": len([c for c in cidrs if c and c != "None"]),
        "has_allow_all_cidr": any(c in ("0.0.0.0/0", "::/0") for c in cidrs),
        "n_port_rules": len(ports),
        "enforced": len(egress) > 0,
    }


def cmd_parse(args):
    files_idx = DATA / f"files_{args.corpus}.jsonl"
    if not files_idx.exists():
        sys.exit(f"Chua co {files_idx}. Chay 'fetch' truoc.")
    out = DATA / f"policies_{args.corpus}.jsonl"
    if out.exists() and not args.append:
        out.unlink()   # parse la idempotent, lam lai tu dau cho sach

    blobs = DATA / "files"
    n_files = n_rec = n_err = 0

    # ghi dem: gom record roi flush theo lo, thay vi mo/dong file moi record
    _buf, _errbuf = [], []

    def emit(rec):
        _buf.append(json.dumps(rec, ensure_ascii=False))
        if len(_buf) >= 2000:
            flush()

    def emit_err(rec):
        _errbuf.append(json.dumps(rec, ensure_ascii=False))

    def flush():
        if _buf:
            with out.open("a", encoding="utf-8") as f:
                f.write("\n".join(_buf) + "\n")
            _buf.clear()
        if _errbuf:
            with (DATA / "parse_errors.log").open("a", encoding="utf-8") as f:
                f.write("\n".join(_errbuf) + "\n")
            _errbuf.clear()

    total_files = sum(1 for _ in jsonl_read(files_idx))
    log(f"Doc {total_files} file...")
    t0 = time.time()

    for f in jsonl_read(files_idx):
        fp = blobs / f["blob"]
        if not fp.exists():
            continue
        n_files += 1
        if n_files % 2000 == 0:
            el = time.time() - t0
            rate = n_files / el if el else 0
            eta = (total_files - n_files) / rate if rate else 0
            log(f"  {n_files}/{total_files} file | {n_rec} record | "
                f"{rate:.0f} file/s | con ~{eta/60:.1f} phut")
        text = fp.read_text(encoding="utf-8", errors="replace")
        ident = {"repo": f["repo"], "path": f["path"], "bytes": f["bytes"]}

        try:
            docs = list(yaml.safe_load_all(text))
        except Exception as e:
            n_err += 1
            emit_err({"key": f["key"], "error": f"{type(e).__name__}: {e}"[:300]})
            continue

        for doc in docs:
            if doc is None:
                continue
            if args.corpus == "ci":
                jobs = doc.get("jobs") if isinstance(doc, dict) else None
                if not isinstance(jobs, dict):
                    continue
                for job_name, job in jobs.items():
                    if not isinstance(job, dict):
                        continue
                    steps = job.get("steps")
                    if not isinstance(steps, list):
                        continue
                    for si, step in enumerate(steps):
                        if not isinstance(step, dict):
                            continue
                        step_text = ""
                        u = str(step.get("uses", "")).strip()
                        if u.startswith("step-security/harden-runner@"):
                            sha = u.split("@", 1)[1].strip()
                            for ln in text.splitlines():
                                if sha and sha in ln:
                                    step_text = ln
                                    break
                        ctx = {"ident": {**ident, "job": str(job_name), "step_idx": si},
                               "step_text": step_text}
                        rec = parse_hr_step(step, ctx)
                        if rec:
                            emit(rec)
                            n_rec += 1
            else:
                rec = parse_k8s_doc(doc, {"ident": ident})
                if rec:
                    emit(rec)
                    n_rec += 1

    flush()
    log(f">>> doc {n_files} file, {n_rec} policy record, {n_err} loi YAML "
        f"({time.time()-t0:.0f}s)")
    log(f">>> {out}")


# ---------------------------------------------------------------- stats

def pct(a, b):
    return f"{100*a/b:.1f}%" if b else "n/a"


def cmd_stats(args):
    log("=" * 62)
    log("CORPUS CI/CD (harden-runner)")
    log("=" * 62)
    recs = list(jsonl_read(DATA / "policies_ci.jsonl"))
    repos_meta = {r["repo"]: r for r in jsonl_read(DATA / "repos_ci.jsonl")}

    if recs:
        repos = {r["repo"] for r in recs}
        blk = [r for r in recs if r["enforced"]]
        blk_ne = [r for r in blk if r["n_endpoints"] > 0]
        blk_repos = {r["repo"] for r in blk_ne}

        log(f"  Tang 0  repo co harden-runner        : {len(repos)}")
        log(f"  Tang 0  step harden-runner           : {len(recs)}")
        log(f"  Tang 1  step egress-policy: block    : {len(blk)}  ({pct(len(blk), len(recs))})")
        log(f"  Tang 2  block + allowlist khong rong : {len(blk_ne)}  ({pct(len(blk_ne), len(recs))})")
        log(f"  Tang 2  repo (corpus THAT SU)        : {len(blk_repos)}  ({pct(len(blk_repos), len(repos))} cua repo)")

        pol = Counter(r["egress_policy"] or "(khong khai bao)" for r in recs)
        log(f"\n  egress-policy: {dict(pol.most_common())}")

        if blk_ne:
            sizes = sorted(r["n_endpoints"] for r in blk_ne)
            log(f"\n  Kich thuoc allowlist: min={sizes[0]} p25={sizes[len(sizes)//4]} "
                f"median={median(sizes):.0f} p75={sizes[3*len(sizes)//4]} max={sizes[-1]}")
            wc = sum(1 for r in blk_ne if r["n_wildcards"] > 0)
            log(f"  Co it nhat 1 wildcard: {wc} ({pct(wc, len(blk_ne))})")

            hosts = Counter()
            for r in blk_ne:
                hosts.update(r["hosts"])
            log(f"\n  Top 25 host duoc allow (dau vao cho phan tich co-tenancy):")
            for h, c in hosts.most_common(25):
                log(f"    {c:6d}  {h}")
            log(f"  Tong host unique: {len(hosts)}")

        pin = Counter(r["version_pin"] for r in recs)
        log(f"\n  Kieu pin version: {dict(pin)}")
        vers = Counter(r["version_semver"] or "(khong ro)" for r in recs)
        log(f"  Top version: {dict(vers.most_common(10))}")
        tier = Counter(r["tier_signal"] for r in recs)
        log(f"  Tier signal: {dict(tier)}")

        # v2.16.0 = ban va DoH bypass (GHSA-46g3-37rh-v698)
        def before_216(v):
            if not v:
                return None
            m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(v).strip())
            if not m:
                return None          # 'v2', 'main', 'master' -> khong ket luan duoc
            return tuple(int(x) for x in m.groups()) < (2, 16, 0)
        known = [before_216(r["version_semver"]) for r in recs]
        known = [k for k in known if k is not None]
        if known:
            log(f"  Version < v2.16.0 (chua va DoH bypass): "
                f"{sum(known)}/{len(known)} ({pct(sum(known), len(known))})")

        if repos_meta:
            stars = sorted(m.get("stars") or 0 for m in repos_meta.values())
            log(f"\n  Stars repo: median={median(stars):.0f} max={stars[-1]}")
            ot = Counter(m.get("owner_type") for m in repos_meta.values())
            log(f"  Owner type: {dict(ot)}")
            arch = sum(1 for m in repos_meta.values() if m.get("archived"))
            log(f"  Archived: {arch} ({pct(arch, len(repos_meta))})")
    else:
        log("  (chua co du lieu)")

    log("\n" + "=" * 62)
    log("CORPUS KUBERNETES (NetworkPolicy / Cilium)")
    log("=" * 62)
    k = list(jsonl_read(DATA / "policies_k8s.jsonl"))
    if k:
        log(f"  Policy record            : {len(k)}")
        log(f"  Repo unique              : {len({r['repo'] for r in k})}")
        log(f"  Kind                     : {dict(Counter(r['kind'] for r in k))}")
        log(f"  Enforcement type         : {dict(Counter(r['enforcement_type'] for r in k))}")
        withe = [r for r in k if r["n_egress_rules"] > 0]
        log(f"  Co egress rule           : {len(withe)} ({pct(len(withe), len(k))})")
        fq = [r for r in k if r["n_fqdns"] > 0]
        log(f"  Co toFQDNs               : {len(fq)}")
        wc = sum(1 for r in k if r["n_wildcards"] > 0)
        log(f"  Co wildcard FQDN         : {wc}")
        allow_all = sum(1 for r in k if r.get("has_allow_all_cidr"))
        log(f"  Co CIDR 0.0.0.0/0        : {allow_all} ({pct(allow_all, len(k))})")
        allf = Counter()
        for r in fq:
            allf.update(r["fqdns"])
        if allf:
            log(f"\n  Top 20 FQDN duoc allow:")
            for h, c in allf.most_common(20):
                log(f"    {c:6d}  {h}")
    else:
        log("  (chua co du lieu)")

    log("\n" + "=" * 62)
    log("KIEM TRA CHAT LUONG (nho truoc khi bao cao con so)")
    log("=" * 62)
    tr = list(jsonl_read(DATA / "truncated.log"))
    if tr:
        lost = sum(t["total"] - 1000 for t in tr)
        log(f"  ! {len(tr)} query bi cap 1000, uoc mat ~{lost} ket qua.")
        log(f"    -> Bao cao trong Limitations. Corpus la SAMPLE, khong phai census.")
    else:
        log("  OK khong query nao bi cap 1000")
    pe = list(jsonl_read(DATA / "parse_errors.log"))
    log(f"  {len(pe)} file loi YAML (bao cao ty le nay trong paper)")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="code search -> candidates")
    d.add_argument("--corpus", choices=["ci", "k8s"], required=True)
    d.add_argument("--extra-query", help="them mot query tuy y")
    d.set_defaults(fn=cmd_discover)

    f = sub.add_parser("fetch", help="tai metadata + noi dung file")
    f.add_argument("--corpus", choices=["ci", "k8s"], required=True)
    f.add_argument("--limit", type=int, help="chi xu ly N repo (de test nhanh)")
    f.add_argument("--no-expand", action="store_true",
                   help="khong tree-expand, chi lay dung file search tra ve")
    f.set_defaults(fn=cmd_fetch)

    p = sub.add_parser("parse", help="YAML -> policy record")
    p.add_argument("--corpus", choices=["ci", "k8s"], required=True)
    p.add_argument("--append", action="store_true")
    p.set_defaults(fn=cmd_parse)

    s = sub.add_parser("stats", help="in con so tong hop")
    s.set_defaults(fn=cmd_stats)

    load_dotenv_simple()   # nap .env NEU co, truoc khi bat ky lenh nao can GITHUB_TOKEN

    args = ap.parse_args()
    DATA.mkdir(exist_ok=True)
    try:
        args.fn(args)
    except KeyboardInterrupt:
        print("\n[!] Dung boi nguoi dung. Du lieu da ghi van con.")
        print("    discover/fetch: chay lai lenh cu, no tu bo qua phan da xong.")
        print("    parse: chay lai tu dau (nhanh, chi vai phut).")
        sys.exit(130)


if __name__ == "__main__":
    main()
