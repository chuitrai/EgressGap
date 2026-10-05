#!/usr/bin/env python3
"""
decision_tree_learnable.py - Task 4: thu decision tree (depth<=6) tren vung
domain "hoc duoc" (5-50/698 repo, xem build_learnable_bucket.py).

KHUNG DIEN GIAI (thong nhat truoc khi chay, xem plan_b_deep_research_prompt.md
Task 4 + verdict Q2 - PHAI giu dung khi viet paper):
    - Day la 1 GIA THUYET can kiem chung, KHONG phai ket qua chac thang. Cay
      co the chi tai tao lai cluster rule tay da co (sigstore/docker/
      security_scanners), khong phat hien gi moi - ca 2 kha nang deu la ket
      qua hop le, phai bao ca 2.
    - Ly do dung cay KHONG PHAI "DL thua tabular data" (Grinsztajn et al.
      NeurIPS 2022 do o quy mo ~10K dong, khac han quy mo vai tram dong cua
      TEEP; o quy mo nho, TabPFN/TabPFN-2.5 (2025-2026) thang tree ve accuracy)
      - ly do dung la DIEN GIAI DUOC (doc ra bang rule, review tung dong -
        quan trong cho 1 cong cu egress-allowlist can giai thich duoc VI SAO
        moi domain duoc cho phep).
    - Nguong 4 khoang tan suat la heuristic tu de xuat (xem build_learnable_
      bucket.py), khong phai quy uoc chuan.

THIET KE
    Feature (X) = MA TRAN NHI PHAN "rule nao trong static_rules.json khop
        VAN BAN workflow cua repo nay" (~23 cot, dung LAI dung engine khop
        cua build_d_static.py, KHONG doan lai). Day la khong gian tin hieu
        GIONG HET S1 dang dung - muc dich la so sanh cong bang: "voi CUNG
        1 tap tin hieu quan sat duoc, cay hoc duoc gi khac hon quy tac tay?"
        Them 1 cot phu: ngon ngu chinh cua repo (one-hot, top 6 ngon ngu).

    Label (y) = domain X co trong declared_hosts (allowlist THAT) cua repo
        do khong (1/0) - cho TUNG domain trong vung 5-50 repo.

    Danh gia = Stratified 5-fold CV (n nho, lop duong hiem - khong tach
        train/test 1 lan vi qua nhay voi seed). Cay CUOI dung de doc ra bang
        rule duoc fit tren TOAN BO du lieu (khong phai 1 fold) - RIENG BIET
        voi cay dung de danh gia CV, dung nham lan 2 muc dich.

    Baseline so sanh = neu domain da co san trong 1 rule cua static_rules.json,
        tinh Precision/Recall CUA CHINH RULE DO tren DUNG CUNG 5 test fold da
        dung cho cay, roi lay trung binh CUNG CACH (mean cua 5 fold-score) -
        v2 (2026-09-12): ban dau tinh baseline tren TOAN BO 698 repo cung 1
        luc (khong tach fold) trong khi cay duoc danh gia bang trung binh 5
        fold rieng - bi phat hien la SO SANH KHONG CONG BANG (2 cach gop so
        khac nhau, cung ho loi voi ratio-of-medians vs median-of-ratios da
        sua o Task 2) - da sua triet de, xem muc "v2" duoi day.

    Kiem tra ON DINH giua cac fold (v2, MOI): voi moi domain, luu lai dac
        trung split GOC (root) cua CA 5 cay-theo-fold (dung de tinh CV) +
        cay cuoi (fit toan bo du lieu) - neu 5 cay chon 5 dac trung goc KHAC
        NHAU, day la dau hieu RO RANG cua bat on dinh/overfit (khong phai suy
        doan tu doc 1 cay duy nhat nhu ban v1). Bao cao ty le dong thuan
        (agreement rate) thay vi khang dinh "overfit" bang loi mo ta cam tinh.

    So mau duong MOI FOLD (v2, MOI): domain co n_pos nho (~9-10/698) thi moi
        fold test chi co ~2 mau duong - F1 tren 1 fold nhu vay rat nhieu
        nhieu (high variance). Bao cao ca min/max n_pos qua 5 fold test, gan
        co "canh bao low-support" ro rang cho domain nao co fold nao <3 mau
        duong, thay vi de nguoi doc tu suy ra tu n_repo tong.

CHAY
    pip install scikit-learn --break-system-packages   # neu chua co
    uv run python measurement/decision_tree_learnable.py
"""
from teep import paths as _P
import json
import re
from collections import defaultdict, Counter
from pathlib import Path

try:
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier, export_text
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import precision_score, recall_score, f1_score
except ImportError:
    raise SystemExit("Thieu scikit-learn/numpy. Chay: pip install scikit-learn numpy --break-system-packages")

DATA = _P.data("data")
SELECTED = json.loads(Path(str(_P.data("measurement/taskb_selected_repos.json"))).read_text(encoding="utf-8"))["selected"]
BUCKETS = json.loads(Path(str(_P.data("measurement/domain_frequency_buckets.json"))).read_text(encoding="utf-8"))
STATIC_RULES = json.loads(Path(str(_P.config("static_rules.json"))).read_text(encoding="utf-8"))["rules"]
for r in STATIC_RULES:
    r["_re"] = [re.compile(p, re.I) for p in r["patterns"]]

OUT_JSON = Path(str(_P.data("measurement/decision_tree_results.json")))
OUT_TXT = Path(str(_P.data("measurement/decision_tree_rules.txt")))


def load_eff_paths_by_repo(selected_repos):
    by_repo = {}
    with open(DATA / "policies_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["repo"] not in selected_repos:
                continue
            ep = (r.get("egress_policy") or "").strip()
            enforced = r.get("enforced")
            if enforced is None:
                enforced = ep == "block"
            if not enforced or r.get("uses_templating") or not r.get("hosts"):
                continue
            by_repo.setdefault(r["repo"], set()).add(r["path"])
    return by_repo


def load_blob_index():
    idx = {}
    with open(DATA / "files_ci.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            idx[(r["repo"], r["path"])] = r["blob"]
    return idx


def matched_rule_ids_for_repo(repo, paths, blob_idx):
    """Union rule_id khop tren TAT CA file enforced cua repo nay."""
    matched = set()
    for path in paths:
        blob_name = blob_idx.get((repo, path))
        if not blob_name:
            continue
        fpath = DATA / "files" / blob_name
        if not fpath.exists():
            continue
        try:
            txt = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for r in STATIC_RULES:
            if r["id"] in matched:
                continue
            if any(rx.search(txt) for rx in r["_re"]):
                matched.add(r["id"])
    return matched


def domain_covered_by_rules(domain):
    """Tra ve list rule_id nao da khai bao san domain nay trong static_rules.json."""
    out = []
    for r in STATIC_RULES:
        if domain in [d.lower() for d in r["domains"] if not d.startswith("*.")]:
            out.append(r["id"])
    return out


def root_split_feature(clf, feature_names):
    """Dac trung dung o node GOC (node 0) cua 1 cay da fit. None neu cay
    khong split duoc gi (chi 1 la duy nhat - vd qua it du lieu train sau khi
    tach fold). Dung de kiem tra ON DINH giua cac fold - KHONG doc 1 cay duy
    nhat roi ket luan overfit nhu ban v1."""
    f_idx = clf.tree_.feature[0]
    if f_idx < 0:  # -2 = TREE_UNDEFINED, node goc la la
        return None
    return feature_names[f_idx]


def main():
    selected_repos = {c["repo"] for c in SELECTED}
    eff_paths = load_eff_paths_by_repo(selected_repos)
    blob_idx = load_blob_index()

    rule_ids = [r["id"] for r in STATIC_RULES]
    languages_all = [c.get("language") or "unknown" for c in SELECTED]
    top_langs = sorted(set(languages_all), key=lambda l: -languages_all.count(l))[:6]

    # X: 1 hang / repo (chi repo co >=1 file eff - khop dung tap dung de xay D_static)
    repos_ordered = [c["repo"] for c in SELECTED if c["repo"] in eff_paths]
    print(f"[*] Repo co van ban de trich feature (>=1 file enforced): {len(repos_ordered)}/{len(SELECTED)}")

    feature_names = list(rule_ids) + [f"lang={l}" for l in top_langs]
    X_rows = []
    repo_lang = {c["repo"]: (c.get("language") or "unknown") for c in SELECTED}
    repo_declared = {c["repo"]: set(h.lower() for h in (c.get("declared_hosts") or [])) for c in SELECTED}

    matched_cache = {}
    for repo in repos_ordered:
        matched = matched_rule_ids_for_repo(repo, eff_paths[repo], blob_idx)
        matched_cache[repo] = matched
        row = [1 if rid in matched else 0 for rid in rule_ids]
        row += [1 if repo_lang[repo] == l else 0 for l in top_langs]
        X_rows.append(row)
    X = np.array(X_rows, dtype=int)

    learnable = BUCKETS["5-50"]
    print(f"[*] Vung hoc duoc: {len(learnable)} domain (5-50/{BUCKETS['n_repo_total']} repo)")

    results = []
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for entry in learnable:
        domain = entry["domain"]
        y = np.array([1 if domain in repo_declared[repo] else 0 for repo in repos_ordered], dtype=int)
        n_pos = int(y.sum())
        if n_pos < 5 or n_pos > len(y) - 5:
            continue  # an toan CV (can >=5 mau moi lop moi fold co y nghia)

        covering_rules = domain_covered_by_rules(domain)

        # --- Cay danh gia bang CV + baseline tinh tren DUNG CUNG test fold
        # (v2 - sua bug so sanh khong cong bang cua ban v1, xem docstring) ---
        cv_p, cv_r, cv_f1 = [], [], []
        base_p, base_r, base_f1 = [], [], []
        fold_n_pos_test = []
        fold_root_features = []

        for train_idx, test_idx in skf.split(X, y):
            fold_n_pos_test.append(int(y[test_idx].sum()))

            clf = DecisionTreeClassifier(max_depth=6, min_samples_leaf=3,
                                          class_weight="balanced", random_state=42)
            clf.fit(X[train_idx], y[train_idx])
            pred = clf.predict(X[test_idx])
            cv_p.append(precision_score(y[test_idx], pred, zero_division=0))
            cv_r.append(recall_score(y[test_idx], pred, zero_division=0))
            cv_f1.append(f1_score(y[test_idx], pred, zero_division=0))
            fold_root_features.append(root_split_feature(clf, feature_names))

            if covering_rules:
                pred_baseline_fold = np.array([
                    1 if any(rid in matched_cache[repos_ordered[i]] for rid in covering_rules) else 0
                    for i in test_idx
                ])
                base_p.append(precision_score(y[test_idx], pred_baseline_fold, zero_division=0))
                base_r.append(recall_score(y[test_idx], pred_baseline_fold, zero_division=0))
                base_f1.append(f1_score(y[test_idx], pred_baseline_fold, zero_division=0))

        # --- Cay CUOI, fit tren TOAN BO du lieu - CHI de doc ra bang rule,
        # KHONG dung de tinh diem (danh gia van la CV o tren) ---
        final_tree = DecisionTreeClassifier(max_depth=6, min_samples_leaf=3,
                                             class_weight="balanced", random_state=42)
        final_tree.fit(X, y)
        rule_text = export_text(final_tree, feature_names=feature_names)
        final_root_feature = root_split_feature(final_tree, feature_names)

        # --- On dinh giua cac fold: 5 cay-fold + 1 cay-cuoi co chon CUNG
        # dac trung o node goc khong? Ty le dong thuan THAP = dau hieu that
        # cua bat on dinh/overfit (khong phai doc 1 cay roi ket luan cam tinh
        # nhu ban v1). ---
        all_root_features = fold_root_features + [final_root_feature]
        non_none = [f for f in all_root_features if f is not None]
        if non_none:
            mode_feature = Counter(non_none).most_common(1)[0][0]
            agreement = sum(1 for f in all_root_features if f == mode_feature) / len(all_root_features)
        else:
            mode_feature, agreement = None, 0.0

        baseline = None
        if covering_rules:
            baseline = {
                "rule_ids": covering_rules,
                "precision_cv_mean": round(float(np.mean(base_p)), 3),
                "recall_cv_mean": round(float(np.mean(base_r)), 3),
                "f1_cv_mean": round(float(np.mean(base_f1)), 3),
            }

        results.append({
            "domain": domain,
            "n_repo": entry["n_repo"],
            "n_pos_in_feature_subset": n_pos,
            "n_repo_in_feature_subset": len(y),
            "fold_n_pos_test_min": min(fold_n_pos_test),
            "fold_n_pos_test_max": max(fold_n_pos_test),
            "low_support_warning": min(fold_n_pos_test) < 3,
            "tree_cv_precision_mean": round(float(np.mean(cv_p)), 3),
            "tree_cv_recall_mean": round(float(np.mean(cv_r)), 3),
            "tree_cv_f1_mean": round(float(np.mean(cv_f1)), 3),
            "root_feature_per_fold": fold_root_features,
            "root_feature_final_tree": final_root_feature,
            "root_feature_agreement": round(agreement, 2),
            "baseline_existing_rule": baseline,
            "rule_text": rule_text,
        })

    OUT_JSON.write_text(
        json.dumps({"n_domains_evaluated": len(results),
                    "n_domains_skipped_too_few_positive": len(learnable) - len(results),
                    "results": [{k: v for k, v in r.items() if k != "rule_text"} for r in results]},
                   indent=1, ensure_ascii=False),
        encoding="utf-8")

    with OUT_TXT.open("w", encoding="utf-8") as f:
        for r in results:
            warn = "  [!] LOW-SUPPORT (fold co it nhat 1 lan <3 mau duong o test)" if r["low_support_warning"] else ""
            f.write(f"{'='*70}\ndomain: {r['domain']}  (n_repo={r['n_repo']}, "
                     f"CV P={r['tree_cv_precision_mean']} R={r['tree_cv_recall_mean']} "
                     f"F1={r['tree_cv_f1_mean']}){warn}\n")
            f.write(f"so mau duong o test moi fold: min={r['fold_n_pos_test_min']} max={r['fold_n_pos_test_max']}\n")
            f.write(f"dac trung o node goc, tung fold: {r['root_feature_per_fold']}  "
                    f"| cay-cuoi(toan bo du lieu): {r['root_feature_final_tree']}  "
                    f"| ty le dong thuan: {r['root_feature_agreement']}\n")
            if r["baseline_existing_rule"]:
                b = r["baseline_existing_rule"]
                f.write(f"baseline (rule {b['rule_ids']}, tinh CUNG CACH tren CUNG 5 test fold): "
                        f"P={b['precision_cv_mean']} R={b['recall_cv_mean']} F1={b['f1_cv_mean']}\n")
            else:
                f.write("baseline: KHONG co rule nao trong static_rules.json khai bao domain nay\n")
            f.write(f"\n{r['rule_text']}\n")

    print(f"\n[*] Da danh gia {len(results)}/{len(learnable)} domain "
          f"(bo qua {len(learnable) - len(results)} domain vi qua it mau duong/am cho CV 5-fold)")

    n_have_rule = sum(1 for r in results if r["baseline_existing_rule"])
    n_tree_higher_cv_f1 = sum(
        1 for r in results if r["baseline_existing_rule"]
        and r["tree_cv_f1_mean"] > r["baseline_existing_rule"]["f1_cv_mean"]
    )
    n_low_support = sum(1 for r in results if r["low_support_warning"])
    n_unstable = sum(1 for r in results if r["root_feature_agreement"] < 0.6)

    print(f"[*] {n_have_rule}/{len(results)} domain co rule tay de doi chieu CONG BANG "
          f"(baseline tinh tren CUNG 5 test fold voi cay, khong phai toan bo corpus)")
    print(f"[*]   trong so do, cay CV F1 cao hon: {n_tree_higher_cv_f1}/{n_have_rule} "
          f"(chua ket luan 'thang/thua' - can doc rule_text + do dong thuan tung ca)")
    print(f"[*] {n_low_support}/{len(results)} domain LOW-SUPPORT (co fold test <3 mau duong "
          f"- F1 cua domain nay nhieu nhieu, doc than trong)")
    print(f"[*] {n_unstable}/{len(results)} domain co dac trung goc BAT ON DINH giua 5 fold "
          f"(ty le dong thuan <0,6 - dau hieu overfit/khong tong quat hoa duoc)")
    print(f">>> {OUT_JSON}")
    print(f">>> {OUT_TXT} (bang rule doc duoc + do on dinh + so mau moi fold)")


if __name__ == "__main__":
    main()
