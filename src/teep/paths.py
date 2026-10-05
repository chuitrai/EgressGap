"""Single source of truth for every filesystem location used by TEEP.

Code lives in this repository. All data -- raw crawl output, the parsed
corpus, and every per-repository derived file -- lives OUTSIDE it, in a
directory that mirrors the project's original logical layout:

    $TEEP_DATA/data/            parsed corpus (*.jsonl); data/files/ = raw workflow YAML
    $TEEP_DATA/measurement/     derived JSON; taskb_run_data/ incl. raw run logs
    $TEEP_DATA/cotenancy/       DNS resolution of corpus hosts
    $TEEP_DATA/tranco/          Tranco top-1M list and its resolution
    $TEEP_DATA/analysis/        per-item outputs of exploratory scripts

Set the TEEP_DATA environment variable to use another location; the default
is a sibling folder ``../teep_data`` next to this repository. Nothing in the
repository itself contains crawled data, so it is safe to publish as is.
"""
import os
from pathlib import Path

PKG = Path(__file__).resolve().parent              # src/teep
REPO = PKG.parent.parent                             # repository root
CONFIG = PKG / "config"                              # hand-authored inputs (public)
RESULTS = REPO / "results"                           # aggregate results (public)
DATA_ROOT = Path(os.environ.get("TEEP_DATA", REPO.parent / "teep_data")).resolve()
REPORT = Path(os.environ.get("TEEP_REPORT", REPO.parent / "report")).resolve()


def data(rel: str) -> Path:
    """Location under DATA_ROOT, addressed by its original logical name,
    e.g. ``data("measurement/residual_capacity.json")``."""
    return DATA_ROOT / rel


def config(name: str) -> Path:
    """Hand-authored configuration shipped with the code, e.g. static_rules.json."""
    return CONFIG / name
