#!/usr/bin/env python3
"""
policy_duplication_analysis.py - Phan tich chi tiet hien tuong trung lap (Duplication)
trong tap du lieu Enforced Network Policies.

CUNG CAP CAC SO LIEU HOC THUAT CHO PAPER:
  1. So luong va ty le % Policy co duplicate.
  2. So luong va ty le % Repository co duplicate.
  3. Bep tach 2 loai duplicate:
     - Exact duplicate: Khai bao trung nguyen van chuoi endpoint.
     - Port variance / collision: Khai bao cung host tren nhieu port (e.g. :80 va :443).
  4. Tong so luot trung lap tong the (= 613 luot chenh lech giua raw va deduplicated).
  5. Top cac host va repo bi duplicate nhieu nhat.
"""

from teep import paths as _P
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


def clean_host(endpoint_str):
    """Tach hostname, bo port va giao thuc."""
    raw = str(endpoint_str).strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0].split(":")[0]
    return raw


def parse_endpoint(endpoint_str):
    """Tach FQDN va Port."""
    raw = str(endpoint_str).strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0]
    if ":" in raw:
        parts = raw.split(":")
        return parts[0], parts[1], raw
    return raw, "443", raw


def main():
    parser = argparse.ArgumentParser(
        description="Phan tich Duplicate trong Policy va Repo"
    )
    parser.add_argument(
        "--src",
        default=str(_P.data("data/policies_ci.jsonl")),
        help="Duong dan toi file policies_ci.jsonl",
    )
    parser.add_argument(
        "--out",
        default=str(_P.data("duplication_report.json")),
        help="File JSON xuat ket qua",
    )
    args = parser.parse_args()

    src_path = Path(args.src)
    if not src_path.exists():
        raise SystemExit(f"[!] Khong tim thay file: {src_path}")

    # Bien dem tong the
    total_policies = 0
    all_repos = set()
    total_raw_endpoints_count = 0
    total_dedup_hosts_count = 0

    # Policy-level metrics
    policies_with_exact_dup = set()  # Chua trung nguyen van chuoi
    policies_with_port_collision = (
        set()
    )  # Chua cung host nhung khac port (hoac 1 co port 1 khong)
    policies_with_any_dup = set()  # Chua bat ky loai duplicate nao

    # Repo-level metrics
    repos_with_exact_dup = set()
    repos_with_port_collision = set()
    repos_with_any_dup = set()

    # Thong ke chi tiet theo Host va Repo
    dup_count_by_host = Counter()  # Host -> so luot bi duplicate thua
    dup_count_by_repo = Counter()  # Repo -> so luot endpoint bi thua

    # Cross-step duplicate trong cung Repo (Policy cloning)
    repo_policy_sets = defaultdict(list)

    # Danh sach log chi tiet tung truong hop de inspect
    detailed_dups = []

    with src_path.open(encoding="utf-8") as f:
        for line_idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)

            # Loc nghiem ngat tap Enforced Policy
            if not r.get("enforced") or r.get("uses_templating"):
                continue

            eps = r.get("endpoints") or r.get("hosts") or []
            if not eps:
                continue

            total_policies += 1
            repo = r.get("repo", "unknown")
            all_repos.add(repo)
            policy_key = (
                repo,
                r.get("path"),
                r.get("job"),
                r.get("step_idx", line_idx),
            )

            raw_eps = [str(e).strip().lower() for e in eps]
            total_raw_endpoints_count += len(raw_eps)

            # 1. Kiem tra Exact String Duplicate (e.g. ["github.com:443", "github.com:443"])
            raw_counter = Counter(raw_eps)
            exact_dup_in_this_pol = {
                ep: count for ep, count in raw_counter.items() if count > 1
            }

            # 2. Kiem tra Multi-Port Collision sau khi clean host
            # (e.g. ["archive.ubuntu.com:80", "archive.ubuntu.com:443"])
            host_to_raw_eps = defaultdict(list)
            for e in raw_eps:
                h = clean_host(e)
                if h:
                    host_to_raw_eps[h].append(e)

            cleaned_unique_hosts = set(host_to_raw_eps.keys())
            total_dedup_hosts_count += len(cleaned_unique_hosts)

            port_collisions_in_this_pol = {}
            for h, entries in host_to_raw_eps.items():
                if (
                    len(entries) > 1 and len(set(entries)) > 1
                ):  # Cung host nhung raw string khac nhau
                    port_collisions_in_this_pol[h] = entries

            # Tinh tong so duplicate entries bi thua trong policy nay
            # Formula: so entry thua = len(raw) - len(unique cleaned hosts)
            redundancy_in_this_policy = len(raw_eps) - len(cleaned_unique_hosts)

            if redundancy_in_this_policy > 0:
                policies_with_any_dup.add(policy_key)
                repos_with_any_dup.add(repo)
                dup_count_by_repo[repo] += redundancy_in_this_policy

                for h, entries in host_to_raw_eps.items():
                    if len(entries) > 1:
                        excess = len(entries) - 1
                        dup_count_by_host[h] += excess

            if exact_dup_in_this_pol:
                policies_with_exact_dup.add(policy_key)
                repos_with_exact_dup.add(repo)

            if port_collisions_in_this_pol:
                policies_with_port_collision.add(policy_key)
                repos_with_port_collision.add(repo)

            if exact_dup_in_this_pol or port_collisions_in_this_pol:
                detailed_dups.append({
                    "repo": repo,
                    "policy_key": str(policy_key),
                    "exact_duplicates": exact_dup_in_this_pol,
                    "port_collisions": port_collisions_in_this_pol,
                    "redundancy_count": redundancy_in_this_policy,
                })

            # Luu tap hop host de check policy clone trong repo
            repo_policy_sets[repo].append(frozenset(cleaned_unique_hosts))

    # Tinh Cross-Step Policy Cloning trong cung 1 repo
    repos_with_cloned_steps = 0
    total_cloned_policy_steps = 0
    for repo, pol_list in repo_policy_sets.items():
        if len(pol_list) > 1:
            unique_sets = set(pol_list)
            if len(unique_sets) < len(pol_list):
                repos_with_cloned_steps += 1
                total_cloned_policy_steps += len(pol_list) - len(unique_sets)

    total_redundant_entries = (
        total_raw_endpoints_count - total_dedup_hosts_count
    )

    # =========================================================================
    # IN KET QUA VA BAO CAO
    # =========================================================================
    print("=" * 80)
    print("BAO CAO PHAN TICH TRUNG LAP (DUPLICATION & REDUNDANCY ANALYSIS)")
    print("=" * 80)
    print(f"  Tong so Policy xet (Enforced, No-template) : {total_policies:,}")
    print(f"  Tong so Repositories                        : {len(all_repos):,}")
    print(
        f"  Tong so Endpoint trong mang JSON tho (Raw)  : {total_raw_endpoints_count:,}"
    )
    print(
        f"  Tong luot xuat hien sau khi Deduplicate     : {total_dedup_hosts_count:,}"
    )
    print(
        f"  --> TONG SO ENTRY TRUNG LAP BI THUA (CHENH) : {total_redundant_entries:,} (Dung con so 613!)\n"
    )

    print("-" * 80)
    print("1. THONG KE CAP DO POLICY (POLICY-LEVEL DUPLICATION)")
    print("-" * 80)
    n_pol_any = len(policies_with_any_dup)
    n_pol_exact = len(policies_with_exact_dup)
    n_pol_port = len(policies_with_port_collision)
    print(
        f"  Policy co chua BAT KY loai duplicate nao   : {n_pol_any:6,d} / {total_policies:,} ({100*n_pol_any/total_policies:5.2f}%)"
    )
    print(
        f"    - Do trung nguyen van chuoi (Exact Dup)  : {n_pol_exact:6,d} / {total_policies:,} ({100*n_pol_exact/total_policies:5.2f}%)"
    )
    print(
        f"    - Do da cong / port collision            : {n_pol_port:6,d} / {total_policies:,} ({100*n_pol_port/total_policies:5.2f}%)\n"
    )

    print("-" * 80)
    print("2. THONG KE CAP DO REPOSITORY (REPO-LEVEL DUPLICATION)")
    print("-" * 80)
    n_repo_all = len(all_repos)
    n_repo_any = len(repos_with_any_dup)
    n_repo_exact = len(repos_with_exact_dup)
    n_repo_port = len(repos_with_port_collision)
    print(
        f"  Repo co chua policy bi duplicate           : {n_repo_any:6,d} / {n_repo_all:,} ({100*n_repo_any/n_repo_all:5.2f}%)"
    )
    print(
        f"    - Do trung nguyen van chuoi (Exact Dup)  : {n_repo_exact:6,d} / {n_repo_all:,} ({100*n_repo_exact/n_repo_all:5.2f}%)"
    )
    print(
        f"    - Do da cong / port collision            : {n_repo_port:6,d} / {n_repo_all:,} ({100*n_repo_port/n_repo_all:5.2f}%)"
    )
    print(
        f"  Repo copy-paste y nguyen policy giua cac step: {repos_with_cloned_steps:6,d} / {n_repo_all:,} ({100*repos_with_cloned_steps/n_repo_all:5.2f}%)\n"
    )

    print("-" * 80)
    print("3. TOP 15 HOST BI KHAI BAO TRUNG LAP NHIEU NHAT (EXCESS OCCURRENCES)")
    print("-" * 80)
    print(f"  {'STT':<4s} {'Host Name':<45s} {'So luong trung lap':>20s}")
    for idx, (h, cnt) in enumerate(dup_count_by_host.most_common(15), 1):
        print(f"  {idx:<4d} {h:<45s} {cnt:>20,d}")

    print("\n" + "-" * 80)
    print("4. TOP 10 REPO CO NHIEU ENTRY TRUNG LAP NHAT")
    print("-" * 80)
    print(f"  {'STT':<4s} {'Repository':<45s} {'So entry bi thua':>20s}")
    for idx, (rp, cnt) in enumerate(dup_count_by_repo.most_common(10), 1):
        print(f"  {idx:<4d} {rp:<45s} {cnt:>20,d}")

    # Xuat JSON
    out_data = {
        "summary": {
            "total_policies": total_policies,
            "total_repos": n_repo_all,
            "raw_endpoint_entries": total_raw_endpoints_count,
            "deduplicated_host_occurrences": total_dedup_hosts_count,
            "total_redundant_entries": total_redundant_entries,
        },
        "policy_metrics": {
            "policies_with_any_duplication": n_pol_any,
            "policies_with_any_duplication_pct": round(
                100 * n_pol_any / total_policies, 2
            ),
            "policies_with_exact_string_duplicate": n_pol_exact,
            "policies_with_port_collision": n_pol_port,
        },
        "repo_metrics": {
            "repos_with_any_duplication": n_repo_any,
            "repos_with_any_duplication_pct": round(
                100 * n_repo_any / n_repo_all, 2
            ),
            "repos_with_exact_string_duplicate": n_repo_exact,
            "repos_with_port_collision": n_repo_port,
            "repos_with_cross_step_clones": repos_with_cloned_steps,
        },
        "top_duplicated_hosts": [
            {"host": h, "excess_count": c}
            for h, c in dup_count_by_host.most_common(50)
        ],
        "top_duplicated_repos": [
            {"repo": r, "excess_count": c}
            for r, c in dup_count_by_repo.most_common(50)
        ],
        "details_sample": detailed_dups[:100],
    }

    Path(args.out).write_text(
        json.dumps(out_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n>>> Da luu bao cao chi tiet vao: {args.out}")


if __name__ == "__main__":
    main()