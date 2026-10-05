#!/usr/bin/env python3
"""
extract_parametric_targets.py - Buoc 2: chay Semgrep (kieu Cosseter) tren cac dong
lenh da duoc parametric_locate.py dinh vi, trich domain that su.

INPUT   measurement/parametric_locations.json (tu parametric_locate.py)
        measurement/egress_extract_rules.yaml  (rule Semgrep: curl/wget/git-clone/helm)
OUTPUT  measurement/parametric_targets.json

3 TRUC TAXONOMY DOC LAP (theo thoa thuan):
    category    = step lam gi              (da co tu Task A: HTTP_REQUEST, SOURCE_FETCH, IAC...)
    determinism = dich duoc xac dinh the nao (PARAMETRIC - gia tri nay co dinh cho
                  ca 4 tool trong file nay, khac voi FIXED cua Task A)
    resolution  = RESOLVED / UNRESOLVED / SCRIPT_REFERENCE
                  RESOLVED          -> trich duoc hostname that (vd curl https://foo.com)
                  UNRESOLVED        -> dich la bien shell / GH Actions expression
                                       (vd curl $URL, curl "${{ secrets.X }}")
                  SCRIPT_REFERENCE  -> dich la duong dan local (vd git clone ./vendor/x)

CACH CHAY SEMGREP: batch 1 lan duy nhat tren 1 file bash tong hop (khong spawn
process rieng cho tung dong - se cham). Moi dong trong file tong hop duoc ghi kem
comment sentinel # ORIGIN <idx> ngay truoc no de map nguoc lai locations[idx].

CHAY
    uv run python measurement/extract_parametric_targets.py
    (can: pip install semgrep --break-system-packages, hoac uv add semgrep --dev)
"""
from teep import paths as _P
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

pass  # sys.path hack removed: package imports via teep.*
from teep.scoping.quantify_test_repo_noise import is_noise_repo, is_noise_workflow  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCATIONS = Path(str(_P.data("measurement/parametric_locations.json")))
RULES = Path(str(_P.config("egress_extract_rules.yaml")))
# Ghi file tam ra ngoai thu muc du an (khong sync/persist chung voi may that cua
# nguoi dung) - tranh xung dot quyen giua cac lan chay (moi lan chay sandbox co the
# la 1 container rieng, file cu tao boi container truoc co the khong xoa duoc).
SYNTH_DIR = Path(tempfile.gettempdir()) / "teep_synth_parametric"
CHUNK_SIZE = 25  # so dong lenh / 1 file synth - can bang giua toc do va cach ly loi parse
OUT = Path(str(_P.data("measurement/parametric_targets.json")))

RULE_ID_BY_TOOL = {
    "curl": "curl-url-extraction",
    "wget": "wget-url-extraction",
    "git clone": "git-clone-extraction",
    "helm": "helm-url-extraction",
}


def build_synth_dir(locations):
    """Chia thanh nhieu file NHO (CHUNK_SIZE dong lenh/file) thay vi 1 file lon.
    Ly do: Semgrep parse ca file bash nhu MOT KHOI; 1 dong loi cu phap (vd chua
    `${{ ... }}` cua GH Actions, hoac lot vao tu Dockerfile heredoc) lam PARSE
    THAT BAI TOAN BO file va tra ve 0 finding cho MOI dong khac trong cung file -
    da gap thuc te khi thu voi 1 file 2524 dong gop chung. Chia nho vua du de gioi
    han thiet hai (1 chunk loi chi mat CHUNK_SIZE dong, khong phai toan bo), vua
    tranh spawn 1262 file rieng (cham do overhead per-file cua semgrep).
    Tra ve: {chunk_filename: {line_no_trong_file: origin_index}}."""
    import shutil
    if SYNTH_DIR.exists():
        shutil.rmtree(SYNTH_DIR, ignore_errors=True)
    SYNTH_DIR.mkdir(parents=True, exist_ok=True)

    chunk_line_map = {}
    for chunk_start in range(0, len(locations), CHUNK_SIZE):
        chunk = locations[chunk_start:chunk_start + CHUNK_SIZE]
        fname = f"chunk_{chunk_start // CHUNK_SIZE}.sh"
        lines = []
        line_map = {}
        for j, loc in enumerate(chunk):
            origin_idx = chunk_start + j
            lines.append(f"# ORIGIN {origin_idx}")
            lines.append(loc["raw_line"])
            line_map[len(lines)] = origin_idx  # dong lenh la dong vua ghi (cuoi cung)
        (SYNTH_DIR / fname).write_text("\n".join(lines) + "\n", encoding="utf-8")
        chunk_line_map[fname] = line_map
    return chunk_line_map


ISOLATED_RETRY_DIR = Path(tempfile.gettempdir()) / "teep_synth_parametric_retry"


def build_isolated_retry_dir(locations, origin_indices):
    """1 file rieng cho MOI dong trong danh sach origin_indices (cach ly toi da,
    dung khi retry cac dong nam trong chunk bi loi cu phap). Tra ve
    {ten_file: origin_index}."""
    import shutil
    if ISOLATED_RETRY_DIR.exists():
        shutil.rmtree(ISOLATED_RETRY_DIR, ignore_errors=True)
    ISOLATED_RETRY_DIR.mkdir(parents=True, exist_ok=True)
    line_map = {}
    for idx in origin_indices:
        fname = f"{idx}.sh"
        (ISOLATED_RETRY_DIR / fname).write_text(locations[idx]["raw_line"] + "\n", encoding="utf-8")
        line_map[fname] = idx
    return line_map


def run_semgrep(target_dir=None):
    target_dir = target_dir or SYNTH_DIR
    base_args = [
        "scan", "--disable-version-check", "--metrics=off", "--no-git-ignore",
        "--jobs", "4", "--json", "--config", str(RULES), str(target_dir),
    ]
    # Uu tien goi binary `semgrep` truc tiep (chay `python -m semgrep` bi deprecated
    # o ban >=1.38 va co the khong in JSON ra stdout dung cach).
    for cmd in ([ "semgrep", *base_args], [sys.executable, "-m", "semgrep", *base_args]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except FileNotFoundError:
            continue
        if proc.stdout.strip():
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                continue
        last_stderr = proc.stderr
    print("!! Semgrep khong tra ve JSON hop le. stderr cuoi:", last_stderr[:2000], file=sys.stderr)
    sys.exit(1)


def extract_candidates(rule_id, message):
    """Tra ve TAT CA candidate hop le trong 1 finding (co the >1, vi 1 dong sinh
    nhieu finding tu cac nhanh pattern-either khac nhau). KHONG tu quyet dinh cai
    nao 'dung' o day - viec chon candidate tot nhat lam o main() (uu tien cai
    RESOLVE duoc), vi $URL/$FLAG-$VAL cua Semgrep khong dam bao la domain that
    (vd co the la "5" tu "--max-time 5" - xem ghi chu trong main())."""
    parts = message.split("|||")
    cands = []
    if rule_id in ("curl-url-extraction", "wget-url-extraction"):
        if len(parts) == 5:
            _, pot, url, feqval, val = parts
            if url != "$URL":
                cands.append(url)
            if feqval != "$FEQVAL" and "=" in feqval:
                cands.append(feqval.split("=", 1)[1])
            if val != "$VAL":
                cands.append(val)
    elif rule_id in ("git-clone-extraction", "helm-url-extraction"):
        if len(parts) == 2:
            _, url = parts
            if url != "$URL":
                cands.append(url)
    return [c.strip().strip("\"'") for c in cands if c and c not in ("$URL", "$FEQVAL", "$VAL")]


DOMAIN_RE = re.compile(r"^[\w.-]+\.[a-zA-Z]{2,}(:\d+)?(/.*)?$")
SCP_GIT_RE = re.compile(r"^[\w.-]+@([\w.-]+):")

# BUG #4 (phat hien qua precision check tay - dung nhu du doan): "wget https://
# github.com/.../release.zip -O main.zip" -> nhanh $FLAG $VAL (them de va flag
# 1-ky-tu) sinh candidate VAL="main.zip", va DOMAIN_RE chap nhan no vi "main.zip"
# co dang "tu.duoi" giong domain. Chan bang cach loai duoi file pho bien khoi
# DOMAIN_RE khi KHONG co "://" di kem (ten file that KHONG bao gio tu dung la 1
# domain hop le trong ngu canh nay).
FILE_EXTENSIONS = {
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "deb", "rpm", "exe",
    "msi", "dmg", "pkg", "iso", "img", "bin", "sh", "jar", "whl", "txt", "json",
    "yaml", "yml", "csv", "log", "conf", "cfg", "ini", "md", "py", "js", "css",
    "html", "htm", "xml", "png", "jpg", "jpeg", "gif", "svg", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "apk", "appimage", "AppImage",
    # bug #5 (phat hien qua census 96/96 clean RESOLVED, khong phai sample):
    # cung mot loi voi bug #4 nhung o duoi file crypto/supply-chain-security
    # (curl -fsSL "${base}.cert" -o opengrep.cert -> lay nham "opengrep.cert"
    # thay vi nhan ra dich that "${base}.cert" la bien - dynamic_variable_expression).
    "cert", "sig", "sha256", "sha1", "sha512", "asc", "pem", "crt", "key",
    "pub", "sum", "lock", "gpg", "sbom", "spdx", "cdx", "provenance", "intoto",
    "jsonl", "toml", "patch", "diff", "wasm", "so", "dll", "kubeconfig",
}


TOOL_HEAD = {"curl": "curl", "wget": "wget", "git clone": "git", "helm": "helm"}


def reason_category(resolution, reason, loc):
    """4 nhom nguyen nhan (theo yeu cau): dynamic_variable_expression / nested_command /
    complex_syntax_or_malformed / parser_extraction_failure. Muc dich: phan biet gioi han
    THAT cua static analysis (bien/expression - khong cach nao biet truoc duoc) voi gioi
    han cua EXTRACTOR hien tai (nested command, syntax phuc tap - co the va co the khong
    dang vao lam, nhung KHONG phai "Semgrep bo tay voi moi thu")."""
    if resolution == "RESOLVED":
        return None
    if resolution == "SCRIPT_REFERENCE":
        return "local_reference"
    if reason == "shell_or_gha_expression":
        return "dynamic_variable_expression"
    if reason in ("unparseable", "looks_like_filename_not_domain"):
        return "complex_syntax_or_malformed"
    if reason == "no_target_captured":
        first_tok = loc["raw_line"].strip().split()[0].strip("|&;()") if loc["raw_line"].strip() else ""
        expected_head = TOOL_HEAD.get(loc["tool"])
        if first_tok == expected_head:
            # tool dung dau statement nhung van khong bat duoc gi -> Semgrep/rule
            # chua phu (flag chain phuc tap, hoac roi vao 1 trong 4 chunk loi cu phap)
            return "parser_extraction_failure"
        # tool KHONG dung dau statement (vd "sudo curl", "docker exec ... curl",
        # "code=$(curl ...") -> pattern "curl ..." cua Semgrep yeu cau curl la ten
        # lenh, khong phai argument cua lenh khac -> khong khop theo thiet ke, khong
        # phai bug
        return "nested_command"
    return "complex_syntax_or_malformed"


def classify_target(raw):
    if not raw:
        return "UNRESOLVED", None, "no_target_captured"
    t = raw.strip()
    if t.startswith("$") or "${{" in t or t.startswith("${"):
        return "UNRESOLVED", None, "shell_or_gha_expression"
    if t.startswith("./") or t.startswith("../"):
        return "SCRIPT_REFERENCE", None, "local_relative_path"
    if t.startswith("/") and "://" not in t:
        return "SCRIPT_REFERENCE", None, "local_absolute_path"

    m = SCP_GIT_RE.match(t)
    if m:
        return "RESOLVED", m.group(1).lower(), "scp_style_git"

    candidate = t
    if "://" not in candidate:
        if DOMAIN_RE.match(candidate):
            suffix = candidate.split("/")[0].split(":")[0].rsplit(".", 1)[-1].lower()
            if suffix in FILE_EXTENSIONS:
                return "UNRESOLVED", None, "looks_like_filename_not_domain"
            candidate = "https://" + candidate
        else:
            return "UNRESOLVED", None, "unparseable"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return "UNRESOLVED", None, "unparseable"
    if host:
        # BUG DA SUA: kiem tra "$" chi o DAU chuoi raw (line 174) khong bat duoc
        # truong hop bien nam GIUA URL, vd "https://$domain/api" - urlparse van
        # tra ve hostname="$domain" (KHONG phai domain that). Phat hien qua doi
        # chieu voi allowlist khai bao (evaluate_parametric_evidence.py) - domain
        # "$domain" xuat hien trong danh sach "missing", ro rang la bug chu khong
        # phai gap allowlist that. Kiem tra lai truc tiep tren HOSTNAME da parse.
        if "$" in host or "{" in host:
            return "UNRESOLVED", None, "shell_or_gha_expression"
        return "RESOLVED", host.lower(), "parsed_url"
    return "UNRESOLVED", None, "unparseable"


def main():
    if not RULES.exists():
        sys.exit(f"Khong tim thay {RULES}")
    data = json.loads(LOCATIONS.read_text(encoding="utf-8"))
    locations = data["locations"]
    print(f"Dinh vi {len(locations)} dong PARAMETRIC (curl/wget/git-clone/helm).")

    chunk_line_map = build_synth_dir(locations)
    n_chunks = len(chunk_line_map)
    print(f"Da ghi {len(locations)} dong lenh vao {n_chunks} chunk-file "
          f"({CHUNK_SIZE} dong/file) trong {SYNTH_DIR}, dang chay semgrep...")

    result = run_semgrep()
    findings = result.get("results", [])
    parse_error_files = {
        Path(e["path"]).name for e in result.get("errors", []) if e.get("type") == "Syntax error"
    }
    print(f"Semgrep tra ve {len(findings)} finding tho; {len(parse_error_files)} chunk-file loi cu phap.")

    per_origin_candidates = {}  # idx -> list[str]
    for f in findings:
        fname = Path(f["path"]).name
        line_map = chunk_line_map.get(fname)
        if line_map is None:
            continue
        origin_idx = line_map.get(f["start"]["line"])
        if origin_idx is None:
            continue
        rule_id = f["check_id"].split(".")[-1]
        msg = f["extra"]["message"].strip()
        cands = extract_candidates(rule_id, msg)
        if cands:
            per_origin_candidates.setdefault(origin_idx, []).extend(cands)

    # THIEU 3 (fix, khong chi bao cao 2 ty le): cac chunk loi cu phap duoc RETRY
    # rieng, moi dong trong chunk do tach thanh 1 file doc lap (mat cach ly toi da,
    # nhung chi ap dung cho so it dong nay nen khong dang lo ve toc do). Muc tieu:
    # dua 87 dong (4 chunk) tro lai mau so co the resolve duoc, thay vi de chung
    # mac dinh la parser_extraction_failure.
    n_recovered_lines = 0
    n_recovered_findings = 0
    if parse_error_files:
        retry_origin_idx = sorted(
            idx for fname in parse_error_files for idx in chunk_line_map.get(fname, {}).values()
        )
        n_recovered_lines = len(retry_origin_idx)
        print(f"  Retry rieng {n_recovered_lines} dong trong {len(parse_error_files)} chunk loi "
              f"(1 file/dong, cach ly toi da)...")
        retry_line_map = build_isolated_retry_dir(locations, retry_origin_idx)
        retry_result = run_semgrep(target_dir=ISOLATED_RETRY_DIR)
        retry_findings = retry_result.get("results", [])
        for f in retry_findings:
            origin_idx = retry_line_map.get(Path(f["path"]).name)
            if origin_idx is None:
                continue
            rule_id = f["check_id"].split(".")[-1]
            msg = f["extra"]["message"].strip()
            cands = extract_candidates(rule_id, msg)
            if cands:
                per_origin_candidates.setdefault(origin_idx, []).extend(cands)
                n_recovered_findings += 1
        print(f"  Retry tra ve finding cho {len(set(retry_line_map[Path(f['path']).name] for f in retry_findings if Path(f['path']).name in retry_line_map))} / {n_recovered_lines} dong.")

    out_rows = []
    resolution_counter = Counter()
    resolved_domains = Counter()
    for i, loc in enumerate(locations):
        cands = per_origin_candidates.get(i, [])
        uniq = list(dict.fromkeys(cands))
        # QUAN TRONG: pattern-either cua Semgrep sinh NHIEU candidate cho 1 dong
        # (vd "curl --max-time 5 --connect-timeout 5 -Iv https://x" sinh ca "5" LAN
        # "https://x" vi $URL chi bi rang buoc "khong giong flag", khong rang buoc
        # "phai giong domain"). KHONG duoc lay uniq[0] mu quang - phai thu classify
        # TUNG candidate, uu tien candidate nao RESOLVED duoc truoc.
        classified = [(*classify_target(c), c) for c in uniq]
        # BUG #4: khi NHIEU candidate cung RESOLVE duoc (vd URL that + gia tri flag
        # -O tinh co giong domain), khong duoc lay candidate dau tien tim thay -
        # uu tien candidate co scheme "://" tuong minh (URL that hau nhu luon co,
        # gia tri flag -o/-O/-H thi khong), tie-break bang do dai (URL that
        # thuong dai hon 1 ten file ngan).
        resolved_cands = [x for x in classified if x[0] == "RESOLVED"]
        if len(resolved_cands) > 1:
            resolved_cands.sort(key=lambda x: ("://" not in x[3], -len(x[3])))
        best = resolved_cands[0] if resolved_cands else None
        if best is None:
            best = next((x for x in classified if x[0] == "SCRIPT_REFERENCE"), None)
        if best is None:
            best = classified[0] if classified else ("UNRESOLVED", None, "no_target_captured", None)
        resolution, domain, reason, target_raw = best
        rcat = reason_category(resolution, reason, loc)
        resolution_counter[resolution] += 1
        if domain:
            resolved_domains[domain] += 1
        is_noise = is_noise_repo(loc["repo"]) or is_noise_workflow(loc["workflow"])
        out_rows.append({
            **{k: loc[k] for k in ("repo", "workflow", "job", "step_index", "line_index", "tool")},
            "raw_line": loc["raw_line"],
            "target_raw": target_raw,
            "ambiguous_candidates": [c for c in uniq if c != target_raw],
            "category": "HTTP_REQUEST" if loc["tool"] in ("curl", "wget")
                        else "SOURCE_FETCH" if loc["tool"] == "git clone" else "IAC",
            "determinism": "PARAMETRIC",
            "resolution": resolution,
            "resolved_domain": domain,
            "resolution_reason": reason,
            "reason_category": rcat,
            "is_test_repo_noise": is_noise,
        })

    total = len(out_rows)
    reason_cat_counter = Counter(r["reason_category"] for r in out_rows if r["reason_category"])

    # THIEU 2 (review): moi con so chinh phai co ban sao "da loc nhieu repo test"
    # ben canh ban "raw" - 74.6% cua 1.262 dong den tu step-security/* tu-test
    # chinh no (xem quantify_test_repo_noise.py). KHONG xoa du lieu, chi tach rieng
    # de bao cao ca hai, tranh danh gia sai muc do dai dien cua corpus.
    clean_rows = [r for r in out_rows if not r["is_test_repo_noise"]]
    clean_resolution_counter = Counter(r["resolution"] for r in clean_rows)
    clean_resolved_domains = Counter(
        r["resolved_domain"] for r in clean_rows if r["resolved_domain"]
    )
    n_clean = len(clean_rows)

    out = {
        "summary": {
            "total_lines": total,
            "resolution_breakdown": dict(resolution_counter),
            "resolution_pct": {k: round(100 * v / total, 1) for k, v in resolution_counter.items()} if total else {},
            "n_distinct_resolved_domains": len(resolved_domains),
            "unresolved_reason_category_breakdown": dict(reason_cat_counter),
            "note_test_repo_noise": (
                "78.0% cua 1.262 dong (984 dong, 12 repo) den tu he sinh thai tu-test/demo/poc "
                "cua step-security (regex 'harden-?runner|step-?security|arm-int-test' tren "
                "owner/repo, hoac workflow ten chua connectivity/test/goat/exfil/canary/poc) - "
                "xem quantify_test_repo_noise.py va test_repo_noise_report.json. Cac field "
                "duoi day la ban DA LOC (n=278 dong con lai, 'sach')."
            ),
            "clean_subset": {
                "n_lines": n_clean,
                "resolution_breakdown": dict(clean_resolution_counter),
                "resolution_pct": {
                    k: round(100 * v / n_clean, 1) for k, v in clean_resolution_counter.items()
                } if n_clean else {},
                "n_distinct_resolved_domains": len(clean_resolved_domains),
            },
        },
        "resolved_domains_frequency": resolved_domains.most_common(),
        "clean_resolved_domains_frequency": clean_resolved_domains.most_common(),
        "rows": out_rows,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 78)
    print(f"KET QUA: {total} dong PARAMETRIC (curl/wget/git-clone/helm)")
    print("=" * 78)
    for k, v in resolution_counter.most_common():
        print(f"  {k:<20}{v:>6}   ({100*v/total:.1f}%)")
    print()
    print(f"  So domain phan biet trich duoc: {len(resolved_domains)}")
    print("  Top 15 domain (dung lam evidence S1):")
    for dom, n in resolved_domains.most_common(15):
        print(f"    {dom:<45}{n}")

    print()
    print("  --- breakdown nguyen nhan UNRESOLVED/SCRIPT_REFERENCE (4 nhom) ---")
    n_unresolved_total = resolution_counter.get("UNRESOLVED", 0) + resolution_counter.get("SCRIPT_REFERENCE", 0)
    for cat, n in reason_cat_counter.most_common():
        pct = 100 * n / n_unresolved_total if n_unresolved_total else 0
        print(f"    {cat:<32}{n:>6}   ({pct:.1f}% cua {n_unresolved_total} khong-resolve)")

    print()
    print(f"  --- ban DA LOC nhieu repo test (n={n_clean}/{total}, xem note_test_repo_noise) ---")
    for k, v in clean_resolution_counter.most_common():
        print(f"    {k:<20}{v:>6}   ({100*v/n_clean:.1f}% cua {n_clean} dong sach)")
    print(f"    So domain phan biet (sach): {len(clean_resolved_domains)}")

    print(f"\n  Da ghi {OUT}")


if __name__ == "__main__":
    main()
