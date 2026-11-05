# GATE-Union: a unified benchmark for runtime enforcement in LLM agents

A harmonised evaluation artifact for [GATE](https://github.com/CharafeddineMechalikh/GATE), a runtime reference monitor that mediates tool calls made by LLM agents. The specification in [SPEC.md](SPEC.md) is frozen and every source below has a recorded licence audit; see [ATTRIBUTION.md](ATTRIBUTION.md).

## What this is, and what it is not

This benchmark combines published agent-security datasets with the GATE original suite and a newly authored stateful set, then maps every case onto the five GATE enforcement stages.

The contribution is the harmonisation schema, the coverage analysis, and the per-layer mapping. It is not a new attack collection. The value of the artifact is that it lets each enforcement property be tested on cases written by other groups where such cases exist, and shows plainly where they do not.

## Sources and provenance

| Source | Kind | Role in this benchmark | Licence verdict |
| --- | --- | --- | --- |
| InjecAgent | published benchmark | external attacks, unauthorized tool use and data stealing | MIT, redistributed with attribution |
| AgentDojo | published benchmark | external attacks plus task utility controls | MIT, attribution; not redistributed |
| SafeClawBench | 2026 preprint | staged capability escalation, and a harm-evidence split we borrow as a metric | MIT, attribution; not redistributed |
| ToolPrivacyBench | 2026 preprint | argument-level and cumulative privacy, the main external supplier for contracts and barriers | unknown licence; not redistributed |
| ASPI | 2026 preprint | ambiguous-state injections, the natural supplier for the escalation band | no licence; fetch script only |
| Agentic prompt-injection 5K and boundary pairs | dataset | benign and hard-negative controls | CC BY 4.0 declared; not redistributed |
| Contemporary Attacks | to be identified | audit pending (task open) | not yet identified |
| GATE original suite | this work | stateful and policy-specific coverage | MIT |
| Authored stateful set | this work | illegal transitions, loops, budgets, drift, cross-tenant | this repo |

Per-source records, including pinned version, case counts before and after mapping, and drop reasons, live in `manifest/*.audit.json` and `manifest/*.notes.md`. Raw downloads are not redistributed here; see [ATTRIBUTION.md](ATTRIBUTION.md) and the licence obligations in SPEC.md section 16.

## Layout

- `SPEC.md` the frozen specification: families, vectors, schema, layer rules, split discipline
- `external/` harmonised rows from other groups' datasets, with provenance on every row
- `gate_original/` the 200-case GATE suite converted to the common schema
- `authored/` newly written cases, date stamped and frozen before any tuning
- `harmonized/` the merged corpus, one JSON lines file per stratum
- `splits/` calibration and test splits, disjoint by template family
- `scripts/` fetchers, normalizers, the layer mapper, dedup, coverage tables
- `results/` per-case monitor runs and the coverage tables they depend on

## The schema in one line

Each case carries its source and original identifier, a canonical attack family naming the violated property, an attack vector naming how the malicious operation was introduced, the tool call with arguments, the execution context including prior state, the expected outcome, and the primary plus secondary enforcement layers. Family and vector are separate axes; see SPEC.md sections 3 and 4.

## Using it

The loader returns rows from one split and does not require GATE installed; it exposes the common schema and a thin adapter that turns a row into a tool-call interception request. Split selection is by template family, so threshold calibration and evaluation cannot share a template.

`python scripts/load.py --split test --stratum external` prints the cases in that slice.

## Citation and reproduction

A tagged release will be archived for a DOI before the manuscript claims it. Until then cite the repository at the commit you used, and record the commit in your results.

## Licence and attribution

The material authored for this repository is released under the MIT License (see
[LICENSE](LICENSE)). Third-party datasets keep their own licences. Only InjecAgent
(MIT, attribution) contributes redistributed case content; every other audited source
is represented here by its audit record and, where permitted, a pinned fetch script,
not by wholesale case data. See [ATTRIBUTION.md](ATTRIBUTION.md) and SPEC.md section 16.
