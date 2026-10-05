"""Regression test: every headline number in the paper, recomputed from the
pipeline outputs, must match the frozen values in golden_numbers.json.

Run after re-running the pipeline (see README):
    PYTHONPATH=src python -m pytest tests -q        # or: python tests/test_paper_numbers.py

The outputs live outside the repository (TEEP_DATA, see src/teep/paths.py), so
this test needs the data directory to be present. It is skipped otherwise.
"""
import json
import statistics as st
from pathlib import Path

from teep import paths as P

GOLDEN = json.loads((Path(__file__).parent / "golden_numbers.json").read_text())


def _load(rel):
    return json.loads(P.data(rel).read_text(encoding="utf-8"))


def current_numbers():
    tf = _load("measurement/tighten_full_corpus.json")
    rc = _load("measurement/residual_capacity.json")
    wb = _load("measurement/would_break_result.json")
    rho = _load("measurement/rho_intersection_result.json")
    ev = _load("measurement/s1_vs_rexec_evaluation.json")
    df = _load("measurement/domain_frequency_buckets.json")
    mc = _load("measurement/mcnemar_result.json")
    sb = _load("measurement/selection_bias_result.json")
    dh = _load("measurement/doh_count_result.json")
    rb = [r["reach_before"] for r in tf["rows"]]
    ra = [r["reach_after"] for r in tf["rows"]]
    return {
        "n_policy": tf["n"],
        "pct_residual_before_strict": tf["pct_residual_before_strict"],
        "pct_residual_after_strict": tf["pct_residual_after_strict"],
        "pct_residual_before_lenient": tf["pct_residual_before"],
        "pct_residual_after_lenient": tf["pct_residual_after"],
        "residual_capacity_main_strict": rc["main"]["pct_with_residual_strict"],
        "would_break_n_eligible": wb["n_eligible"],
        "would_break_n": wb["n_would_break"],
        "would_break_rate_pct": wb["would_break_rate_pct"],
        "would_break_n_explained_drop_low": wb["n_explained_by_drop_low_suppression"],
        "rho_full_s1_union_rexec_pct": rho["full_s1_union_rexec"]["pct_beyond_required_policy"],
        "rho_subset_pct": rho["subset_with_rexec"]["pct_beyond_required_policy"],
        "s1_micro_recall_evdA": ev["evd_A"]["micro_recall"],
        "s1_eval_n_repo": ev["evd_A"]["n_repo"],
        "n_destinations": df["n_domain_total"],
        "reach_median_before": st.median(rb),
        "reach_median_after": st.median(ra),
        "reach_max_before": max(rb),
        "reach_max_after": max(ra),
        "mcnemar_b_removed": mc["b_TF"],
        "mcnemar_c_added": mc["c_FT"],
        "sel_bias_median_hosts_per_repo_subset":
            sb["declared_hosts_per_repo"]["would_break_subset"]["median"],
        "sel_bias_median_hosts_per_repo_full":
            sb["declared_hosts_per_repo"]["full_corpus"]["median"],
        "doh_n_resolver_endpoints": dh["n_resolver_endpoints"],
        "doh_n_policies_listing_resolver": dh["n_confirmed"],
        "doh_n_repos_listing_resolver": dh["n_confirmed_repos"],
        "doh_n_policies_doh_dot_port": dh["n_doh_dot_port_policies"],
        "doh_n_policies_port53": dh["n_port53"],
    }


def test_paper_numbers_unchanged():
    if not P.DATA_ROOT.exists():
        import pytest
        pytest.skip(f"data directory not found: {P.DATA_ROOT}")
    cur = current_numbers()
    diffs = {k: (GOLDEN[k], cur.get(k)) for k in GOLDEN if cur.get(k) != GOLDEN[k]}
    assert not diffs, f"paper numbers drifted (golden, current): {diffs}"


def test_published_snapshot_matches_golden():
    """Data-free check for reviewers: results/paper_numbers.json (committed,
    aggregates only) must equal the frozen paper values. Needs no private data."""
    snap = json.loads((P.RESULTS / "paper_numbers.json").read_text(encoding="utf-8"))
    diffs = {k: (GOLDEN[k], snap.get(k)) for k in GOLDEN if snap.get(k) != GOLDEN[k]}
    assert not diffs, f"results/paper_numbers.json differs from golden: {diffs}"


if __name__ == "__main__":
    cur = current_numbers()
    bad = 0
    for k, g in GOLDEN.items():
        ok = cur.get(k) == g
        bad += not ok
        print(f"{'OK ' if ok else 'XX '} {k:45s} golden={g!s:10s} now={cur.get(k)}")
    print(f"\n{len(GOLDEN) - bad}/{len(GOLDEN)} match")
    raise SystemExit(bad > 0)
