#!/usr/bin/env python3
"""
expand_doh.py - Mo rong phan giai DNS va phan loai chinh xac DoH/DoT tren tap Enforced Policies.

CAC DIEM DA SUA VA DAM BAO CHUAN CHO PAPER:
  1. Loc nghiem ngat: Chi xet r['enforced'] == True va r['uses_templating'] == False
     (Dong bo 100% voi 6.190 policy va 2.701 host chuan trong summary.txt).
  2. Kiem tra Port khi nhan dien DoH/DoT:
     - Port 443 (hoac default): DoH (DNS-over-HTTPS)
     - Port 853: DoT (DNS-over-TLS)
     - Port 53: DNS truyen thong (Khong tinh la DoH)
     - Port khac (80, 1025...): Khong phai encrypted DNS
  3. Wildcard probing cho phep mo rong resolve tren tap namespace.
"""

from teep import paths as _P
import argparse
import json
import re
import socket
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Danh muc cac nha cung cap Encrypted DNS cong cong pho bien
ENCRYPTED_DNS_PROVIDERS = {
    # Domains
    "cloudflare-dns.com": "Cloudflare",
    "one.one.one.one": "Cloudflare",
    "dns.google": "Google",
    "dns.quad9.net": "Quad9",
    "doh.opendns.com": "OpenDNS",
    "dns.adguard-dns.com": "AdGuard",
    "dns.nextdns.io": "NextDNS",
    "doh.cleanbrowsing.org": "CleanBrowsing",
    # IPs
    "1.1.1.1": "Cloudflare IP",
    "1.0.0.1": "Cloudflare IP",
    "8.8.8.8": "Google IP",
    "8.8.4.4": "Google IP",
    "9.9.9.9": "Quad9 IP",
    "149.112.112.112": "Quad9 IP",
}

# Subdomain mau dung de probe cho cac wildcard pho bien
WILDCARD_PROBES = {
    "blob.core.windows.net": "status.blob.core.windows.net",
    "azureedge.net": "ajax.aspnetcdn.com",
    "cloudfront.net": "d1.cloudfront.net",
    "s3.amazonaws.com": "s3.amazonaws.com",
    "amazonaws.com": "aws.amazon.com",
    "r2.cloudflarestorage.com": "pub-0.r2.cloudflarestorage.com",
    "githubusercontent.com": "raw.githubusercontent.com",
    "actions.githubusercontent.com": "pipelines.actions.githubusercontent.com",
    "github.com": "api.github.com",
    "docker.io": "registry-1.docker.io",
    "sigstore.dev": "fulcio.sigstore.dev",
    "pkg.dev": "us-docker.pkg.dev",
    "quay.io": "cdn.quay.io",
    "codecov.io": "uploader.codecov.io",
}


def parse_endpoint(endpoint_str):
    """
    Tach FQDN va Port chinh xac tu chuoi endpoint.
    Tra ve: (host, port_int, raw_clean)
    """
    raw = str(endpoint_str).strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0]  # Bo path

    if ":" in raw:
        parts = raw.split(":")
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443
    else:
        host = raw
        port = 443  # Mac dinh cac allowlist khong ghi port la 443 (HTTPS)

    return host, port, raw


def get_resolvable_host(host):
    """Chuyen doi wildcard thanh probe domain de resolve IP."""
    if "*" not in host:
        return host
    base = re.sub(r"^[^.]*\*[^.]*\.", "", host.lstrip("*").lstrip("."))
    if base in WILDCARD_PROBES:
        return WILDCARD_PROBES[base]
    return host.replace("*", "probe").lstrip(".")


def resolve_single_host(host):
    """Phan giai IP cua host qua socket getaddrinfo."""
    target = get_resolvable_host(host)
    ips = set()
    try:
        results = socket.getaddrinfo(target, None, socket.AF_INET)
        for item in results:
            ips.add(item[4][0])
    except Exception:
        pass
    return host, target, sorted(list(ips))


def check_encrypted_dns(host, port):
    """
    Kiem tra va gan nhan nghiem ngat DoH / DoT dua tren Domain/IP va Port.
    Tra ve: (protocol_type, provider_name, is_valid_evasion_evidence)
    """
    matched_provider = None
    for prov_domain, prov_name in ENCRYPTED_DNS_PROVIDERS.items():
        if host == prov_domain or host.endswith("." + prov_domain):
            matched_provider = prov_name
            break

    if not matched_provider:
        return None, None, False

    # Phan loai theo Port
    if port == 443:
        return "DoH (DNS-over-HTTPS)", matched_provider, True
    elif port == 853:
        return "DoT (DNS-over-TLS)", matched_provider, True
    elif port == 53:
        return "Standard DNS (Plaintext UDP/TCP)", matched_provider, False
    else:
        return f"Other Port ({port})", matched_provider, False


def main():
    parser = argparse.ArgumentParser(description="DNS Resolution Expansion and Strict DoH Analysis")
    parser.add_argument("--src", default=str(_P.data("data/policies_ci.jsonl")), help="Path to policies_ci.jsonl")
    parser.add_argument("--out", default=str(_P.data("expanded_doh_report.json")), help="Output JSON report")
    parser.add_argument("--workers", type=int, default=30, help="Number of resolver threads")
    args = parser.parse_args()

    src_path = Path(args.src)
    if not src_path.exists():
        raise SystemExit(f"[!] Khong tim thay file: {src_path}")

    # =========================================================================
    # 1. DOC VA LOC DONG BO NGUYEN TAC CORPUS (6.190 Enforced Policies)
    # =========================================================================
    n_policies = 0
    all_repos = set()
    raw_hosts = Counter()           # host -> so luot xuat hien
    host_to_repos = defaultdict(set)
    endpoint_entries = []           # Luu (repo, host, port, raw_str)

    with src_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)

            # [FIX LOI 1]: Loc nghiem ngat nhu analyze.py / psl_classify.py
            if not r.get("enforced") or r.get("uses_templating"):
                continue

            eps = r.get("endpoints") or r.get("hosts") or []
            if not eps:
                continue

            n_policies += 1
            repo = r.get("repo", "unknown")
            all_repos.add(repo)

            for e in eps:
                host, port, raw = parse_endpoint(e)
                if host:
                    raw_hosts[host] += 1
                    host_to_repos[host].add(repo)
                    endpoint_entries.append({
                        "repo": repo,
                        "path": r.get("path"),
                        "job": r.get("job"),
                        "host": host,
                        "port": port,
                        "raw": raw
                    })

    total_unique_hosts = len(raw_hosts)
    total_occurrences = sum(raw_hosts.values())

    print("=" * 78)
    print("PHAN TICH MO RONG RESOLVE VA ENCRYPTED DNS (DOH/DOT) — PHAM VI CHUAN")
    print("=" * 78)
    print(f"  Policy co cuong che (enforced, no-template) : {n_policies:,}")
    print(f"  So repositories rieng biet                 : {len(all_repos):,}")
    print(f"  Tong so unique hosts trong pham vi         : {total_unique_hosts:,}")
    print(f"  Tong luot xuat hien cua host               : {total_occurrences:,}\n")

    # =========================================================================
    # 2. PHAN TICH NGHIEM NGAT DOH / DOT (KIEM TRA PORT)
    # =========================================================================
    print("=" * 78)
    print("KIEM TRA VA PHAN LOAI ENCRYPTED DNS (DOH / DOT / PLAIN DNS)")
    print("=" * 78)

    doh_findings = []
    false_positives = []

    for entry in endpoint_entries:
        proto, provider, is_evasion = check_encrypted_dns(entry["host"], entry["port"])
        if proto:
            item = {
                "repo": entry["repo"],
                "raw_endpoint": entry["raw"],
                "host": entry["host"],
                "port": entry["port"],
                "protocol": proto,
                "provider": provider,
                "valid_evasion_evidence": is_evasion
            }
            if is_evasion:
                doh_findings.append(item)
            else:
                false_positives.append(item)

    # Thong ke cac ca DoH/DoT that
    valid_repos = {x["repo"] for x in doh_findings}
    print(f"  [+] DoH/DoT HOP LE (Port 443 / 853): {len(doh_findings)} entries tren {len(valid_repos)} repo(s)")
    for f in doh_findings:
        print(f"      - {f['raw_endpoint']:<25s} | {f['protocol']:<22s} | Repo: {f['repo']}")

    print(f"\n  [-] FALSE POSITIVES LOAI BO (Port 53 / 80 / 1025...): {len(false_positives)} entries")
    for fp in false_positives:
        print(f"      - {fp['raw_endpoint']:<25s} | {fp['protocol']:<22s} | Repo: {fp['repo']} (Khong phai DoH evasion)")

    # =========================================================================
    # 3. RESOLVE DA LUONG VOI WILDCARD PROBE
    # =========================================================================
    print("\n" + "=" * 78)
    print("RESOLVE DA LUONG VA TINH DO PHU (COVERAGE)")
    print("=" * 78)

    resolved_map = {}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_host = {executor.submit(resolve_single_host, h): h for h in raw_hosts}
        for future in future_to_host:
            orig_h, target, ips = future.result()
            if ips:
                resolved_map[orig_h] = {
                    "probe_target": target,
                    "ips": ips,
                    "count": raw_hosts[orig_h],
                    "repos": len(host_to_repos[orig_h])
                }

    n_resolved = len(resolved_map)
    resolved_occurrences = sum(raw_hosts[h] for h in resolved_map)
    coverage_pct = (resolved_occurrences / max(total_occurrences, 1)) * 100

    print(f"  Host resolve thanh cong                    : {n_resolved:,} / {total_unique_hosts:,}")
    print(f"  Do phu theo luot xuat hien (Weighted Cov.) : {coverage_pct:.2f}%")

    # =========================================================================
    # 4. GHI FILE JSON BAO CAO CHUAN XUAT CHO PAPER
    # =========================================================================
    out_data = {
        "metadata": {
            "enforced_policies": n_policies,
            "total_repos": len(all_repos),
            "total_unique_hosts": total_unique_hosts,
            "resolved_hosts": n_resolved,
            "coverage_pct": round(coverage_pct, 2),
        },
        "doh_dot_analysis": {
            "valid_evasion_entries": doh_findings,
            "valid_repos_count": len(valid_repos),
            "false_positives_excluded": false_positives
        },
        "resolved_hosts": resolved_map
    }

    Path(args.out).write_text(json.dumps(out_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n>>> Da xuat bao cao JSON chuan tai: {args.out}")


if __name__ == "__main__":
    main()