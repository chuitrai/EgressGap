#!/usr/bin/env bash
# Re-run every analysis behind the paper's tables and figures, then check the
# numbers against the frozen values. Requires the private data directory:
#   export TEEP_DATA=/path/to/teep_data     (default: ../teep_data)
# Without the data, run only:  uv run pytest tests -k snapshot
set -euo pipefail
cd "$(dirname "$0")/.."
run() { echo ">>> $*"; uv run python -m "$@"; }

run teep.capacity.compute_residual_capacity      # Fig. 2a, Sec. IV-A  (66.6 / 99.5 %)
run teep.capacity.tighten_full_corpus            # Fig. 2, I' (36.9 / 88.7 %), co-tenant reach
run teep.analysis.compute_would_break            # Sec. IV-B (536/545, 19 fallback)
run teep.analysis.compute_rho_intersection       # Sec. IV-A (43.0 / 42.5 %)
run teep.analysis.compute_selection_bias         # Sec. IV-B (33 vs 20 destinations)
run teep.analysis.compute_mcnemar                # Sec. IV-A (2,118 removed, 0 added)
run teep.runtime.evaluate_s1_vs_rexec            # Rec_S1 = 0.593 (n=602)
run teep.static.build_learnable_bucket           # Fig. 3a (1,803 destinations, 84 %)
run teep.reference.doh_count                     # Sec. IV-A channel (d): 5 / 72 / 2
run teep.figures.export_figure_csvs              # Fig. 2, Fig. 3
run teep.figures.make_figures
run teep.export_public_results                   # results/paper_numbers.json + figures
uv run pytest tests
