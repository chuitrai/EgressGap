#!/usr/bin/env python3
"""
tighten_policy.py - Siet mot egress allowlist ve gan nhu cau thuc.

NGUYEN TAC (don gian, giai thich duoc):
    Giu lai host h trong allowlist NEU co it nhat mot bang chung h duoc CAN:
      - S1: mot rule static du doan h  (workload co lenh can h), HOAC
      - S3: h xuat hien trong traffic capture that (neu co)
    Bo phan con lai (chi co trong khai bao, khong co bang chung).

    tightened(I) = { h in I : justified_by_S1(h) or h in S3 }

LUU Y AN TOAN (ghi vao Limitations):
    - S1 CHUA day du (bang rule con thieu) -> siet chi bang S1 se bo nham
      host hop le. Vi vay tighten CHINH THUC phai dung S1 U S3.
    - Wildcard (vd *.blob.core.windows.net) thuong khong khop rule nao ->
      bi bo. Do la ket qua an ninh mong muon (wildcard la nguon no rong lon
      nhat) nhung co the pha build. Danh dau rieng, khong bo im lang.
    - Khi build that su can mot host bi bo -> DUNG va bao nguoi, khong tu them.

Dung nhu module:
    from teep.capacity.tighten_policy import compile_rules, static_domains, tighten
"""
from teep import paths as _P
import json
import re
from pathlib import Path


def compile_rules(path=str(_P.config("static_rules.json"))):
    rules = json.loads(Path(path).read_text(encoding="utf-8"))["rules"]
    for r in rules:
        r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]
    return rules


def host_matches(pred, host):
    """pred (co the wildcard '*.x') co khop host cu the khong."""
    pred = pred.lower()
    host = host.lower()
    if pred.startswith("*."):
        return host == pred or host.endswith(pred[1:])
    return pred == host


def static_domains(workflow_text, rules, drop_low=True):
    """Tra (domains, provenance, matched_rule_ids) tu phan tich tinh."""
    domains, prov, matched = set(), {}, []
    for r in rules:
        if drop_low and r.get("confidence") == "low":
            # luat 'any_action' phu tro — chi dung khi khong luat nao khac khop
            continue
        if not any(rx.search(workflow_text) for rx in r["_re"]):
            continue
        matched.append(r["id"])
        for d in r["domains"]:
            domains.add(d.lower())
            prov.setdefault(d.lower(), []).append(r["id"])
    # neu KHONG luat chuyen biet nao khop, moi dung luat 'any_action' phu tro
    if not matched:
        for r in rules:
            if r.get("confidence") == "low" and any(rx.search(workflow_text) for rx in r["_re"]):
                matched.append(r["id"])
                for d in r["domains"]:
                    domains.add(d.lower())
                    prov.setdefault(d.lower(), []).append(r["id"])
    return domains, prov, matched


def tighten(declared, s1_domains, s3_hosts=None):
    """Tra (kept, dropped, kept_reason).

    declared  : list host trong allowlist goc
    s1_domains: set domain do S1 du doan
    s3_hosts  : set host quan sat that (None neu chua co)
    """
    s3_hosts = {h.lower() for h in (s3_hosts or set())}
    kept, dropped, reason = [], [], {}
    for h in declared:
        hl = h.lower()
        by_s1 = any(host_matches(d, hl) for d in s1_domains)
        by_s3 = hl in s3_hosts
        if by_s1 or by_s3:
            kept.append(h)
            reason[h] = ("S1+S3" if by_s1 and by_s3 else "S1" if by_s1 else "S3")
        else:
            dropped.append(h)
            reason[h] = "wildcard" if "*" in h else "unjustified"
    return kept, dropped, reason


if __name__ == "__main__":
    # demo nhanh tren mot allowlist gia
    rules = compile_rules()
    txt = "steps:\n  - run: pip install -r requirements.txt\n  - uses: actions/checkout@v4"
    d, prov, m = static_domains(txt, rules)
    print("S1 rules khop:", m)
    print("S1 domains   :", sorted(d))
    declared = ["github.com:443", "pypi.org:443", "files.pythonhosted.org:443",
                "evil-cdn.example.com:443", "*.blob.core.windows.net:443"]
    declared = [x.split(":")[0] for x in declared]
    kept, dropped, reason = tighten(declared, d)
    print("GIU  :", kept)
    print("BO   :", dropped)
    print("ly do:", reason)
