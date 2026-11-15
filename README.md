# GATE-Union: a layered benchmark for runtime enforcement in LLM agents

An evaluation artifact for [GATE](https://github.com/CharafeddineMechalikh/GATE), a runtime
reference monitor that mediates the tool calls an LLM agent makes. This repository ships the
**extended 1,957-case corpus** (schema `1.3`, generator `1.3.0`). It replaces the earlier
1,895-row multi-stratum corpus, which is preserved in the git history and in
[DECISIONS.md](DECISIONS.md); 985 of its rows are imported here as category `X`.

## What this is

The corpus tests each enforcement property at the tool-call boundary, on cases the monitor's
authors did not write where such cases exist, and on newly authored cases where they do not.

- **1,957 cases** = **1,653 malicious** + **304 benign** (9 of the benign tasks are approval-gated).
- **972 authored** (716 attacks, 256 benign) across eleven categories `A`–`K`, plus **985 imported**
  (937 attacks, 48 benign) in category `X`.
- **Three execution levels**: atomic (L1, 1,517), compositional (L2, 197), contextual (L3, 243).
- **Six enforcement layers**: capability, workflow, semantic, ifc, contracts, dcbf, with
  human-in-the-loop (HITL) as the final decision on a withheld call rather than a seventh layer.
- Every case carries a full schema-1.3 record: scenario and threat model, declared environment and
  policy, the expected call sequence, the proposed action, the expected decision
  (`ALLOW` / `DENY` / `REQUIRE_APPROVAL`), the designated enforcing layer, per-layer ground-truth
  labels, and provenance. The designated layer is a per-case design field, so layer attribution is
  not circular.

The contribution is the taxonomy, the coverage discipline and the per-layer mapping, not a new
attack collection. Imported rows keep their source label verbatim.

## Attack taxonomy and layer coverage

The corpus is organised into eleven authored attack categories `A`–`K`, each a family of security
properties with ten subtypes (twenty for `K`), plus the imported category `X`. The counts below are
computed from `gate_union/out/dataset.jsonl`; L1/L2/L3 are the malicious-case execution levels (the
304 benign cases split 255/28/21). Full per-subtype detail, with a representative attack and the
designated layers for every subtype, is in
[gate_union/docs/06_attack_taxonomy.md](gate_union/docs/06_attack_taxonomy.md).

| Cat | Attack category | Attacks | Benign | L1 | L2 | L3 |
|---|---|---|---|---|---|---|
| A | Reconnaissance and information gathering | 61 | 1 | 30 | 15 | 16 |
| B | Unauthorized access and identity abuse | 58 | 2 | 28 | 15 | 15 |
| C | Data-related attacks | 60 | 31 | 30 | 15 | 15 |
| D | Filesystem and operating-system attacks | 64 | 42 | 30 | 15 | 19 |
| E | Network and infrastructure attacks | 83 | 13 | 30 | 15 | 38 |
| F | Web application and API attacks | 59 | 18 | 29 | 15 | 15 |
| G | Email, communication and social engineering | 57 | 24 | 27 | 15 | 15 |
| H | Financial and transactional attacks | 60 | 27 | 30 | 15 | 15 |
| I | Cloud and DevOps attacks | 59 | 25 | 29 | 15 | 15 |
| J | Persistence and security-control interference | 68 | 4 | 30 | 15 | 23 |
| K | AI-agent-specific attacks | 87 | 69 | 32 | 19 | 36 |
| X | Externally sourced cases (imported) | 937 | 48 | 937 | 0 | 0 |
| | **Total** | **1653** | **304** | **1262** | **169** | **222** |

### Which layer owns which attack

Each malicious case designates one enforcing layer that owns the security property it violates, a
per-case design field fixed before any run. Aggregating those designations by category gives the
coverage matrix below. A filled circle marks a principal owner (the layer owns at least 25% of the
category's attacks), a half circle a secondary owner (some, but under 25%), and a dash a layer that
owns no attack in the category. The columns map to the schema layers: Capability `capability`,
FSM `workflow`, Semantic `semantic`, Info-flow `ifc`, Contracts `contracts`, Runtime `dcbf`.
Human-in-the-loop is the final decision on a withheld call, not a seventh enforcement layer.

| Attack category | Capability | FSM | Semantic | Info-flow | Contracts | Runtime |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| A Reconnaissance and information gathering | ● | — | ◐ | ◐ | ◐ | — |
| B Unauthorized access and identity abuse | ● | ◐ | — | ◐ | ◐ | ◐ |
| C Data-related attacks | ◐ | ◐ | — | ● | ◐ | — |
| D Filesystem and operating-system attacks | ◐ | ◐ | ◐ | ◐ | ● | ◐ |
| E Network and infrastructure attacks | ● | — | — | — | ● | ◐ |
| F Web application and API attacks | ◐ | — | — | — | ● | ◐ |
| G Email, communication and social engineering | ◐ | — | ● | ◐ | ◐ | ◐ |
| H Financial and transactional attacks | ◐ | — | ◐ | — | ● | ◐ |
| I Cloud and DevOps attacks | ● | ◐ | ◐ | ◐ | ● | ◐ |
| J Persistence and security-control interference | ● | ◐ | — | — | ● | — |
| K AI-agent-specific attacks | ◐ | ● | ● | ◐ | — | ◐ |
| X Externally sourced cases (imported) | ◐ | ◐ | ◐ | — | ● | ◐ |

The important observation is that **no individual layer is sufficient**. Every category spans
several layers, and no single column covers the taxonomy. Capability is the principal owner of
reconnaissance (A) and access (B) attacks, yet data exfiltration (C) is owned by info-flow. Info-flow
owns exfiltration but owns no attack in network (E) or API (F) abuse. The semantic layer principally
owns email social engineering (G) and AI-agent attacks (K) but owns nothing in network or API abuse.
Contracts is the broadest owner, principal in seven categories and 1,091 of the 1,653 attacks overall,
yet it owns no AI-agent-specific attack (K); the runtime barrier owns only 48 attacks directly and
acts as a cumulative-harm backstop rather than a primary classifier. Capability enforcement can
establish that an agent is allowed to use an email tool, but it cannot establish that sending a
particular confidential document to a particular recipient is legitimate; that judgement needs
info-flow, contracts and the semantic layer together.

The matrix shows the ground-truth property owner, not necessarily the layer that fires first. The
pipeline is deny-dominant, so a case may be stopped at an earlier layer than its designated owner
(an early block); the evaluation reports the designated and first-firing layers as two columns.

## Layout

- `gate_union/out/dataset.jsonl` the corpus, one JSON object per line (1,957 rows)
- `gate_union/out/manifest.json` counts, `dataset_sha256`, schema and generator version
- `gate_union/out/coverage.{md,csv,json}` the per-category and per-subcategory coverage matrix
- `gate_union/out/validation.{md,json}` the eighteen-check QA report
- `gate_union/schema/attack_case.schema.json` the JSON Schema (draft-07)
- `gate_union/generator/` the deterministic authored-case generator
- `gate_union/external/` the importer and the frozen imported rows (`union_external.jsonl`) with provenance
- `gate_union/responses/` the tool-response corpus (109 fixtures, 146 scenarios)
- `gate_union/validate.py` the structural, coverage and separation checks
- `gate_union/docs/` design, evaluation, threat-model and tool-response documentation
- `manifest/` per-source licence audits (provenance for the imported rows)
- `results/` historical measurement artifacts from the retired corpus (provenance only)
- `scripts/` the retired corpus's historical generation and analysis pipeline (provenance only)
- [SPEC.md](SPEC.md) the dataset specification, [DECISIONS.md](DECISIONS.md) the change log,
  [ATTRIBUTION.md](ATTRIBUTION.md) the licence notices

## Using it

Each line of `gate_union/out/dataset.jsonl` is one self-contained case; no GATE installation is
needed to read it. The generator and validator import the GATE framework's `gzt` package
(`gzt.policies.destination_trust`), so rebuilding or validating requires the `gate-zero-trust`
directory of a [GATE](https://github.com/CharafeddineMechalikh/GATE) checkout on `PYTHONPATH`, plus
`jsonschema`:

```
export PYTHONPATH=/path/to/GATE/gate-zero-trust   # provides gzt
python -m gate_union.generator.build              # rebuild gate_union/out/ deterministically
python gate_union/validate.py                     # eighteen checks; exit 1 if any hard check fails
```

The rebuild is byte-reproducible: `dataset_sha256`
`4ed706b94a09a9b8c3d1ec6660e1cab73e26179b9e30488bf89e1153cf7d400f` (verified, 18/18 checks pass).

Evaluation runs through the GATE framework's `gzt` harness, which ships with
[GATE](https://github.com/CharafeddineMechalikh/GATE) (not in this repository):

```
USE_TF=0 USE_TORCH=1 python -m gzt.evaluate --dataset gate_union/out/dataset.jsonl --out target
```

## Provenance and licence

The authored material is released under the MIT License (see [LICENSE](LICENSE)). The 985 imported
rows (category `X`) come from three sources, each with a recorded licence verdict in
`manifest/*.audit.json` and a per-row `provenance` block (source, case id, version pin, licence,
digest):

| Source | Imported rows | Licence | Notice |
| --- | --- | --- | --- |
| InjecAgent | 745 | MIT, attribution | Copyright (c) 2023 Qiusi Zhan |
| GATE original suite | 148 | MIT (this work) | 200 rows less 52 label conflicts |
| SafeClawBench | 92 | MIT, attribution | ClawSecBench Authors |

The held-out AgentDojo suite is never imported; the importer refuses to run if it finds it. See
[ATTRIBUTION.md](ATTRIBUTION.md) for the full notices and the sources audited but not redistributed.

## Citation

A tagged release will be archived for a DOI before the manuscript claims it. Until then, cite the
repository at the commit you used and record that commit in your results.