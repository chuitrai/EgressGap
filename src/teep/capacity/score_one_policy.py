#!/usr/bin/env python3
"""
score_one_policy.py - Danh gia MOT policy don le (khong can chay ca corpus).

TRA LOI CAU HOI: "dua vao 1 allowlist bat ky (tu tay go, hoac 1 policy that
trong corpus) thi co danh gia duoc khong?" - CO, script nay dung LAI dung
logic cua compute_residual_capacity.py (host_channels, LENIENT/STRICT) +
tighten_policy.py (S1, tighten) NHUNG tinh S2 TUOI (fresh) cho tung host
thay vi chi tra s2_reference.json - vi 1 host go tay/1 policy ngoai corpus
co the CHUA tung xuat hien trong s2_reference.json (bang tinh san chi phu
dung tap host cua policies_ci.jsonl tai thoi diem build).

3 CACH DUA INPUT (chon 1):
    1. --hosts "a.com,b.com,c.com"          - go tay danh sach host, phan
       cach bang dau phay (khong can workflow that -> chi co ban TRUOC siet,
       khong co S1/tighten vi khong co text workflow de doi chieu).
    2. --hosts-file duong/dan/hosts.txt      - 1 host moi dong (# la comment).
       Co the them --workflow-file de doi chieu S1 (tighten duoc).
    3. --repo "owner/repo" --path ".github/workflows/x.yml" [--job ten_job]
       - LAY THANG tu corpus that (data/policies_ci.jsonl + data/files_ci.jsonl
       + data/files/*) - tu dong co ca I (declared) LAN text workflow (S1),
       nen LUON tinh duoc ca truoc/sau siet. Dung cach nay khi muon minh hoa
       1 vi du CU THE that trong bai (worked example).

VI DU
    uv run python measurement/score_one_policy.py --hosts \\
        "github.com,api.github.com,pypi.org,files.pythonhosted.org,evil-cdn.example.com,*.blob.core.windows.net"

    uv run python measurement/score_one_policy.py --repo "CarlAllenn/edtf" \\
        --path ".github/workflows/fuzz.yml" --job fuzz

OUTPUT: in bang chi tiet tung host (kenh nao khop, vi sao) + ket luan
LENIENT/STRICT cua CA policy, va neu co S1 thi in them ban SAU SIET.
"""
from teep import paths as _P
import argparse
import json
import re
from pathlib import Path

from teep.capacity.compute_residual_capacity import host_channels, CHANNELS
from teep.reference.build_s2_reference import load_psl, load_lots, psl_class, lots_hit, build_fanin, DOH_RESOLVERS
from teep.capacity.tighten_policy import compile_rules, static_domains, tighten

DATA = _P.data("data")


def classify_fresh(hosts, icann, private, lots, ip2dom, resolved):
    """Tinh S2 TUOI cho 1 danh sach host bat ky (khong can co san trong
    s2_reference.json) - dung LAI dung logic build_s2_reference.py."""
    table = {}
    for h in hosts:
        hl = h.lower().strip()
        cls, why, suf = psl_class(hl, icann, private)
        lt = lots_hit(hl, lots)
        ips = resolved.get(hl) or []
        cotenants = set()
        for ip in ips:
            cotenants |= (ip2dom.get(ip, set()) - {hl})
        flags = []
        if "*" in hl:
            flags.append("wildcard")
        if cls == "A":
            flags.append("open_namespace")
        if lt:
            flags.append("lots")
        if hl.split(":")[0] in DOH_RESOLVERS:
            flags.append("doh_resolver")
        if len(cotenants) >= 1:
            flags.append("shared_ip")
        table[hl] = {
            "psl_class": cls, "lots_match": lt, "n_cotenants": len(cotenants),
            "cotenant_sample": sorted(cotenants)[:4], "flags": flags,
        }
    return table


def strict_channels_for(policy_channels):
    out = set(policy_channels) & set(CHANNELS)
    if "lots" in out and "lots_discretionary" not in policy_channels:
        out.discard("lots")
    return out


def print_report(label, hosts, s2_fresh):
    print(f"\n{'='*90}\n{label}  ({len(hosts)} host)\n{'='*90}")
    print(f"{'host':45s} {'kenh':30s} {'chi tiet'}")
    print("-" * 90)
    policy_channels = set()
    for h in hosts:
        hl = h.lower().strip()
        ch, found = host_channels(hl, s2_fresh)
        policy_channels |= ch
        info = s2_fresh.get(hl, {})
        detail = []
        if "shared_ip" in ch:
            detail.append(f"chia IP voi {info.get('n_cotenants',0)} domain (vd {info.get('cotenant_sample',[])[:2]})")
        if "lots_mandatory_github" in ch:
            detail.append(f"LOTS-github BAT BUOC (match='{info.get('lots_match')}')")
        elif "lots_discretionary" in ch:
            detail.append(f"LOTS TU CHON (match='{info.get('lots_match')}')")
        if "doh_resolver" in ch:
            detail.append("la 1 resolver DoH cong khai")
        if "wildcard_or_open_ns" in ch:
            detail.append(f"wildcard/open-namespace (psl_class={info.get('psl_class')})")
        main_ch = ch & set(CHANNELS)
        print(f"{hl:45s} {','.join(sorted(main_ch)) or '(khong)':30s} {'; '.join(detail)}")

    has_lenient = len(policy_channels) > 0
    strict = strict_channels_for(policy_channels)
    has_strict = len(strict) > 0
    print("-" * 90)
    print(f"  LENIENT (tinh ca LOTS-github bat buoc): {'CO ro ri' if has_lenient else 'SACH'} "
          f"- kenh: {sorted(policy_channels & set(CHANNELS)) or '(khong)'}")
    print(f"  STRICT  (loai LOTS-github-bat-buoc-don-thuan): {'CO ro ri' if has_strict else 'SACH'} "
          f"- kenh: {sorted(strict) or '(khong)'}")
    return has_lenient, has_strict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", help="danh sach host, phan cach bang dau phay")
    ap.add_argument("--hosts-file", help="file 1 host/dong")
    ap.add_argument("--workflow-file", help="file workflow YAML that de doi chieu S1 (tuy chon)")
    ap.add_argument("--repo", help="lay thang tu corpus: ten repo (vd owner/repo)")
    ap.add_argument("--path", help="duong dan workflow trong corpus (di kem --repo)")
    ap.add_argument("--job", help="loc theo ten job (tuy chon, di kem --repo)")
    ap.add_argument("--policies", default=str(_P.data("data/policies_ci.jsonl")))
    ap.add_argument("--files-index", default=str(_P.data("data/files_ci.jsonl")))
    ap.add_argument("--rules", default=str(_P.config("static_rules.json")))
    ap.add_argument("--psl", default=str(_P.config("public_suffix_list.dat")))
    ap.add_argument("--lots", default=str(_P.config("lots.json")))
    ap.add_argument("--resolved", default=str(_P.data("cotenancy/resolved.json")))
    ap.add_argument("--tranco", default=str(_P.data("tranco/resolved_top100000.jsonl")))
    a = ap.parse_args()

    workflow_text = None
    declared = []

    if a.repo:
        if not a.path:
            raise SystemExit("--repo can di kem --path")
        with open(a.policies, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r["repo"] != a.repo or r.get("path") != a.path:
                    continue
                if a.job and r.get("job") != a.job:
                    continue
                declared = sorted({h.lower() for h in (r.get("hosts") or [])})
                print(f"[*] Tim thay policy trong corpus: {a.repo} {a.path} job={r.get('job')} "
                      f"enforced={r.get('enforced')} n_hosts={len(declared)}")
                break
        if not declared:
            raise SystemExit(f"Khong tim thay policy khop {a.repo} {a.path} (job={a.job}) "
                              f"trong {a.policies}")
        blob_of = {}
        with open(a.files_index, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line)
                blob_of[(d["repo"], d["path"])] = d["blob"]
        blob = blob_of.get((a.repo, a.path))
        if blob and (DATA / "files" / blob).exists():
            workflow_text = (DATA / "files" / blob).read_text(encoding="utf-8", errors="replace")
            print(f"[*] Doc duoc workflow text tu corpus ({blob}) -> se tinh ca S1/tighten")
        else:
            print(f"[!] Khong tim thay blob workflow trong {a.files_index} -> CHI tinh duoc truoc siet")
    elif a.hosts:
        declared = sorted({h.lower().strip() for h in a.hosts.split(",") if h.strip()})
    elif a.hosts_file:
        lines = Path(a.hosts_file).read_text(encoding="utf-8").splitlines()
        declared = sorted({l.strip().lower() for l in lines if l.strip() and not l.startswith("#")})
    else:
        raise SystemExit("Can 1 trong 3: --hosts | --hosts-file | --repo+--path")

    if a.workflow_file:
        workflow_text = Path(a.workflow_file).read_text(encoding="utf-8", errors="replace")
        print(f"[*] Doc workflow text tu {a.workflow_file} -> se tinh ca S1/tighten")

    if not declared:
        raise SystemExit("Danh sach host khai bao (I) rong - khong co gi de danh gia")

    print(f"[*] I (declared) = {len(declared)} host: {declared}")

    icann, private = load_psl(a.psl)
    lots, lots_ver = load_lots(a.lots)
    resolved = json.loads(Path(a.resolved).read_text(encoding="utf-8")) if Path(a.resolved).exists() else {}
    ip2dom = build_fanin(a.tranco) if Path(a.tranco).exists() else {}
    print(f"[*] PSL {len(icann)+len(private)} suffix | LOTS {len(lots)} hau to (v{lots_ver}) | "
          f"co-tenancy {len(resolved)} host resolved | fan-in {len(ip2dom):,} IP")

    s2_before = classify_fresh(declared, icann, private, lots, ip2dom, resolved)
    print_report("TRUOC SIET (I = allowlist khai bao)", declared, s2_before)

    if workflow_text is None:
        print("\n[!] Khong co text workflow (--workflow-file hoac --repo+--path tim thay blob) "
              "-> KHONG tinh duoc S1/tighten. Chi co ket qua TRUOC SIET o tren.")
        return

    rules = compile_rules(a.rules)
    s1, prov, matched = static_domains(workflow_text, rules)
    kept, dropped, reason = tighten(declared, s1, set())
    print(f"\n[*] S1 khop {len(matched)} rule: {matched}")
    print(f"[*] S1 du doan {len(s1)} domain can dung: {sorted(s1)[:10]}{'...' if len(s1)>10 else ''}")
    print(f"[*] Sau siet: giu {len(kept)}/{len(declared)}, bo {len(dropped)} host: {dropped}")

    s2_after = classify_fresh(kept, icann, private, lots, ip2dom, resolved)
    print_report("SAU SIET (I' = giu host co bang chung S1)", kept, s2_after)


if __name__ == "__main__":
    main()
