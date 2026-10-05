# EgressGap — reachability beyond declared hostnames in CI/CD egress allowlists

Code and aggregate results for *"EgressGap: Measuring Reachability Beyond
Declared Hostnames in CI/CD Egress Allowlists"* (paper: `https://github.com/chuitrai/EgressGap`).

The study mines 7,137 enforcing allowlists from public GitHub Actions workflows
that use Harden-Runner (`egress-policy: block`), measures how often enforcement
admits destinations the policy does not list, how much of that survives
tightening the allowlist to what static analysis justifies, and what that
tightening would break. A controlled SNI/Host test is in a separate repository
(`egress-testbed`).

**This repository contains code, hand-authored configuration and aggregate
results only.** The crawled corpus, raw workflow files and CI run logs contain
third-party repository names and logs and are not distributed (see *Data*).

## Three levels of checking

| Level | Needs | What you can verify |
|---|---|---|
| **1. Numbers** (1 min) | this repo only | every number quoted in the paper equals the frozen value: `uv run pytest tests -k snapshot` |
| **2. Code** (10 min) | this repo only | read the exact definitions behind each equation (table below); `results/figures/` are the paper's Fig. 2 and 3 |
| **3. Full re-run** (hours) | private data dir + GitHub token | re-derive every number from the corpus: `scripts/reproduce_all.sh` |

## Paper → code map

| Paper item | Module (`python -m teep.<module>`) | Output |
|---|---|---|
| Policy filter, n = 7,137 (Table I) | `capacity.compute_residual_capacity.load_policies` | — |
| Channel rate P(𝓘), Eq. 1; 66.6 % strict / 99.5 % lenient; κ(h) per host | `capacity.compute_residual_capacity` (`host_channels`) | Fig. 2a |
| Tightened policy I′, Eq. 2; 36.9 % / 88.7 %; 2,118 removed, 0 added; co-tenant reach 7 → 3, max 6,307 → 313 | `capacity.tighten_policy` (`host_matches` = *m*), `capacity.tighten_full_corpus`, `analysis.compute_mcnemar` | Fig. 2 |
| ρ̂ intersection, ≤ 43.0 % (42.5 % subset) | `analysis.compute_rho_intersection` | — |
| Coverage failure F, Eq. 3; 536/545 = 98.4 %; 19 fallback-rule cases | `analysis.compute_would_break` | Fig. 3b |
| Rec_S1, Eq. 4; 0.593 on n = 602 | `runtime.evaluate_s1_vs_rexec` | — |
| 1,803 destinations, 84 % in < 5 repositories | `static.build_learnable_bucket` | Fig. 3a |
| Selection bias, median 33 vs 20 destinations | `analysis.compute_selection_bias` | — |
| Channel (d): 5 policies / 4 repos list a resolver, 2 with DoH/DoT port, 72 bare port-53 | `reference.doh_count` | — |
| Run-selection fault 45.9 % → 14.0 %, Table II chain 698/657/560/547/545 | `runtime.audit_log_validity`, `analysis.compute_would_break` | Table II |
| Fig. 2, Fig. 3 | `figures.export_figure_csvs`, `figures.make_figures` | `results/figures/` |
| Controlled SNI/Host test, Table III (11,050 B, SHA-256 match) | repository `egress-testbed` | — |

`results/paper_numbers.json` holds all 28 headline values; `tests/golden_numbers.json`
is the frozen copy the tests compare against.

## Layout

```
src/teep/
  paths.py              every filesystem location, in one place ($TEEP_DATA)
  config/               hand-authored inputs: static_rules.json (S1 rule table),
                        lots.json, egress_extract_rules.yaml, public_suffix_list.dat
  collection/           harvest enforcing workflows from GitHub (hr_crawl.py)
  scoping/              filter test/demo repos, select the runtime-evidence subset
  static/               S1: static prediction of required destinations
  reference/            S2: PSL, co-tenancy, abuse catalogue, DNS-resolver signals
  runtime/              R_exec: parse Harden-Runner DNS audit records from run logs
  capacity/             reachability expansion before/after tightening
  analysis/             coverage failure, rho-intersection, selection bias, monotonicity
  figures/              Fig. 2 and Fig. 3
  tools/, exploratory/  standalone tools and early analyses (not used for headline results)
results/                aggregate numbers and figures (public; no per-repo rows)
tests/                  golden numbers + data-free snapshot test
scripts/reproduce_all.sh
```

## Setup

```
uv sync                                   # installs the `teep` package (src layout)
export TEEP_DATA=/path/to/teep_data       # default: ../teep_data next to this repo
uv run pytest tests -k snapshot           # level 1, no data needed
```

All scripts are modules: `uv run python -m teep.<package>.<script>`.

## Data

Data is addressed through `teep.paths.data("<logical name>")` and lives in `$TEEP_DATA`:

```
$TEEP_DATA/data/           parsed corpus (policies_ci.jsonl); data/files/ = raw workflow YAML
$TEEP_DATA/measurement/    derived outputs; taskb_run_data/logs/ = raw CI run logs
$TEEP_DATA/cotenancy/      DNS resolution of corpus hosts
$TEEP_DATA/tranco/         Tranco top-1M (downloaded 2 Aug 2026) and its resolution
```

Not distributed: it holds crawled repository names and CI logs. To rebuild it you
need a GitHub token in a local `.env` (`GITHUB_TOKEN=...`, git-ignored) and several
hours of API time: `python -m teep.collection.hr_crawl discover --corpus ci`, then
the scripts in `teep.runtime` for the run-log side. Code search is not a stable
snapshot, so a new crawl will give a somewhat different corpus; aggregate results
for the paper's corpus are in `results/`.

External references used (all fetched before the paper's analysis date):

| Reference | Version used |
|---|---|
| Public Suffix List | snapshot of 27 Aug 2026 (`config/public_suffix_list.dat`) |
| LOTS Project domains | MISP warninglist `lots-project`, version 20241010 (`config/lots.json`) |
| Tranco top-1M | list downloaded 2 Aug 2026 |
| DNS resolver list | hand-compiled (62 endpoints) from the curl DoH wiki and provider documentation: `reference/doh_count.py` |
| Harden-Runner | action v2.21.1, agent v0.16.3 (controlled test only) |

## Known reproducibility gap

The co-tenant reach *maximum* (6,307 / 313) depends on `cotenancy/resolved.json`
covering every corpus host. That file was later overwritten by a 24-host
cross-check, so recomputing `tighten_full_corpus` today reproduces every
percentage and the median but not the maximum. Rebuild the full resolution first:
`python -m teep.reference.dns_cotenancy resolve --domains-file <all corpus hosts>`.

## Ethics

Only public repositories and public CI logs were read. The controlled test used a
repository we control, contacted only public infrastructure and transmitted no
data. Per-repository results are withheld so that individual projects are not
singled out.

## License

Code: Apache-2.0 (`LICENSE`). The paper and third-party data (PSL, LOTS list,
Tranco) are under their own terms.

## Citation

See `CITATION.cff`.
