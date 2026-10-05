"""Write the public, aggregate-only results into the repository's results/ folder.

Everything under $TEEP_DATA stays private (it contains crawled repository names
and per-repository rows). This script copies out only:
  results/paper_numbers.json   every headline number in the paper (aggregates)
  results/figures/*.pdf        Fig. 2 and Fig. 3 as built by teep.figures.make_figures

Run after the pipeline:  python -m teep.export_public_results
"""
import json
import shutil
import sys
from pathlib import Path

from teep import paths as P

sys.path.insert(0, str(P.REPO / "tests"))
from test_paper_numbers import current_numbers  # noqa: E402  (single definition of the numbers)


def main():
    out = P.RESULTS
    (out / "figures").mkdir(parents=True, exist_ok=True)
    nums = current_numbers()
    (out / "paper_numbers.json").write_text(json.dumps(nums, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out / 'paper_numbers.json'} ({len(nums)} numbers)")
    for name in ("fig2_reachability.pdf", "fig3_coverage.pdf"):
        src = P.REPORT / name
        if src.exists():
            shutil.copy2(src, out / "figures" / name)
            print(f"copied {name}")
        else:
            print(f"!! missing {src} - run: python -m teep.figures.make_figures")


if __name__ == "__main__":
    main()
