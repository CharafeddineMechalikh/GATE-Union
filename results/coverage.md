# Coverage of GATE-Union by source

Cells are counted cases, taken from the per-source audits in `manifest/`, not from the upstream papers. A `0` is a measurement: the source was fetched, its structure was read, and it does not label that property. `prompt-level only` means the dataset exists and was counted but ships no tool call, so nothing can be mapped onto a mediated boundary. `no public data` means the artefact could not be located at all.

## Table A, family by source

| family | property | injecagent | agentdojo | safeclawbench | toolprivacybench | aspi | agentic_pi_5k | gate_original | authored | sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F01 | granted-tool boundary | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 21 | 0 | 1 |
| F02 | role capability | 0 | 16 | 0 | no public data | prompt-level only | prompt-level only | 2 | 0 | 2 |
| F03 | tenant isolation | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 21 | 0 | 1 |
| F04 | instruction versus intent | 0 | 101 | 67 | no public data | prompt-level only | prompt-level only | 3 | 0 | 3 |
| F05 | harm inside the grant | 476 | 73 | 126 | no public data | prompt-level only | prompt-level only | 15 | 0 | 4 |
| F06 | disclosure boundary | 544 | 342 | 158 | 0 | prompt-level only | prompt-level only | 20 | 0 | 4 |
| F07 | irreversible state change | 17 | 40 | 50 | no public data | prompt-level only | prompt-level only | 24 | 0 | 4 |
| F08 | argument validity | 0 | 0 | 0 | 0 | prompt-level only | prompt-level only | 0 | 0 | 0 |
| F09 | code policy | 17 | 0 | 66 | no public data | prompt-level only | prompt-level only | 13 | 0 | 3 |
| F10 | transition legality | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 2 | 90 | 2 |
| F11 | phase loop bound | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 2 | 50 | 2 |
| F12 | step budget | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 9 | 60 | 2 |
| F13 | cumulative privacy | 0 | 16 | 0 | 0 | prompt-level only | prompt-level only | 10 | 120 | 3 |
| F14 | accumulated envelope | 0 | 0 | 0 | no public data | prompt-level only | prompt-level only | 8 | 140 | 2 |
| F15 | semantic masking | 0 | 20 | 0 | no public data | prompt-level only | prompt-level only | 0 | 0 | 1 |
| F16 | network scope | 0 | 21 | 0 | no public data | prompt-level only | prompt-level only | 16 | 0 | 2 |
| F17 | persistent memory | 0 | 0 | 133 | no public data | prompt-level only | prompt-level only | 0 | 0 | 1 |

## Table B, enforcement layer by source

The layer axis is the one the paper's claim lives on, so this is the table that decides how much authoring a defensible corpus needs.

| layer | injecagent | agentdojo | safeclawbench | toolprivacybench | aspi | agentic_pi_5k | gate_original | authored | external total | authored share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| privilege | 0 | 37 | 0 | 0 | 0 | 0 | 60 | 0 | 37 | 0% |
| dfa | 0 | 0 | 0 | 0 | 0 | 0 | 13 | 200 | 0 | 94% |
| contracts | 1054 | 455 | 400 | 0 | 0 | 0 | 57 | 0 | 1909 | 0% |
| semantic | 0 | 121 | 67 | 0 | 0 | 0 | 18 | 0 | 188 | 0% |
| dcbf | 0 | 16 | 0 | 0 | 0 | 0 | 18 | 260 | 16 | 88% |

## What the two tables say

- 10 of 17 families have any external supply at all.
- Families with zero external supply: F01, F03, F08, F10, F11, F12, F14.
- The two stages with zero external supply across every audited source are dfa and dcbf. Their cases are the authored stratum, and the authored share column above is the number a reviewer should read as the cost of the gap, not as a claim about the field.
- Where several families share one owning layer, extra rows for those families do not buy a new invariant test. F01, F02, F03 and F16 are all privilege-stage properties, and F05, F06, F07, F08 and F09 are all contract properties, which is why the corpus quota is set per layer and not per family.
- Row counts here are before template dedup, and the difference is not cosmetic. The 1,054 InjecAgent rows are 62 attacker scenarios against 17 user tools, and the 731 rows the normalizer emits collapse to 43 templates. The contracts layer therefore looks far better supplied in rows than it is in distinct attacks, and the layer supply of privilege, at 37 external rows across every audited source, is the thin one.
