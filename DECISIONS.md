# GATE-Union decision log

Running record of why the benchmark is built the way it is, with the measurement behind each decision. This exists so the reviewer response can cite evidence rather than intent. Newest entries at the end.

## D1, 2026-11-03, the corpus is harmonised, not concatenated

Decision. Keep every source independently executable and store a common-schema artifact beside it, with provenance on each row.

Why. Reviewer 1 stated that concatenating test cases is not a methodological contribution, and that the datasets do not describe attacks at the same level of abstraction: InjecAgent is organised by attacker objective, AgentDojo by user task plus injected objective, the GATE suite by the runtime property violated.

Evidence. The GATE original suite alone shows what concatenation would hide: 200 rows collapse to 89 distinct attack templates, so 111 rows restate a template already present. InjecAgent is a 62 attacker scenarios by 17 user tools matrix, so 1,054 rows are 62 distinct attacks, verified from the fetched artefact rather than from the paper.

Consequence. Every reported count states whether it is rows or templates. Aggregates never appear without per-family and per-layer denominators.

## D2, 2026-11-03, attack family and attack vector are separate fields

Decision. `attack_family` names the violated property, `attack_vector` names how the malicious operation was introduced. A case has exactly one family and at most one vector.

Why. Conflating them is what makes a benchmark look diverse while testing one thing. Data exfiltration is an objective, indirect prompt injection is a delivery method, and most external datasets vary only the delivery method.

Evidence. The reviewer's own coverage grid marks indirect prompt injection as covered by all eight sources, which is exactly the failure mode this separation exposes.

Consequence. Coverage tables are computed on family, so a source that supplies 500 injection cases in five costumes shows as five cases of one property, not five hundred.

## D3, 2026-11-03, quotas are set by enforcement layer, not by family

Decision. Target about 200 attacks per primary layer, five layers, so 1,000 attacks, plus about 300 benign controls.

Why. The paper's central testable claim is that five stages are complementary. That claim is falsified or supported per stage, so the corpus must be sized per stage. Balancing seventeen families was my own initial proposal and it was wrong: it manufactures authoring work, and it measures the taxonomy rather than the architecture.

Evidence. External supply by layer, measured for the first audited source: InjecAgent places 1,054 rows in the contracts column and zero in privilege, semantic, DFA and D-CBF. No audited source labels an illegal state transition or a budget violation.

Consequence. Privilege, contracts and semantic can be filled from published data. DFA and D-CBF must be authored, and that is disclosed as a limitation of the field rather than concealed by inflating other families.

## D4, 2026-11-03, authored cases are frozen before any tuning is inspected

Decision. Stateful cases are written from the specification and the stage definitions, committed with a date and hash, before thresholds or semantic prototypes are adjusted against them.

Why. The reviewers already suspect that the benchmark and the operating points were built together, and a benchmark whose gaps are filled by its own authors after watching the monitor is not evidence.

Consequence. Where authored and external results diverge, both are reported and the divergence is discussed.

## D5, 2026-11-03, the two readings that matter are external only and full corpus

Decision. Every headline number is reported twice, once on the external stratum and once including the authored stratum.

Why. External cases supply validity, authored cases supply coverage of our own claims. A single blended figure lets one hide inside the other.

Consequence. Agreement between the two is the finding; disagreement is also the finding, and is not smoothed.

## D6, 2026-11-03, splits are made by template family

Decision. Calibration and test splits are disjoint by `template_family`, never by case row, and threshold selection plus semantic prototype construction touch only the calibration split.

Why. Reviewer 2 noted that deterministic reproducibility does not establish experimental independence, and Reviewer 1 required that thresholds and prototypes not be selected on the cases used for evaluation. With 111 duplicate rows in 200 cases, a random row split would leak almost immediately.

Consequence. The loader exposes the split discipline so a reviewer gets it by calling one function rather than trusting a sentence in the paper.

## D7, 2026-11-03, about 200 cases per family or layer is enough, and 20 is not

Decision. Keep the corpus near 1,300 rows rather than chasing several thousand.

Why and evidence. Interval width for a family that blocks 90 percent of its cases, computed with Wilson score intervals:

| Cases in the group | 95 percent interval |
| --- | --- |
| 20 | [69.9, 97.2] |
| 30 | [74.4, 96.5] |
| 59 | [79.5, 95.3] |
| 100 | [82.6, 94.5] |

Consequence. Below about 30 cases a family cannot support a claim. Above about 60 the statistical gain per extra case is small, so inflating near-duplicate injection corpora buys interval width we do not need while weakening the diversity argument.

## D8, 2026-11-03, the coverage table reports counts, not judgments

Decision. Replace the Yes, Partial, No grid with two count tables, source by family and layer by provenance stratum.

Why. A judgment cell can be disputed; a counted cell can be checked. The grid also invites reading "Partial" as "supplied", which D1 shows it is not.

Consequence. The tables are generated from the harmonised rows, so they cannot drift from the data.

## D9, 2026-11-03, declared gaps rather than silent drops

- Persistent memory, family F17. Three sources mark it covered, GATE cannot express it because the mediated tool surface has no memory read or write. Either the surface is extended or the family stays out of scope, stated in the threat model.
- Cross-tenant access, family F03. No audited source models tenancy, so the GATE original database-scope cases stand in for it, and the substitution is labelled as an approximation.
- Multi-step degradation. A case whose meaning depends on prior calls loses that meaning if the prior state is not carried; such cases are marked degraded and excluded from sequence and barrier scoring rather than kept as easy single-call wins.
- Sandboxing. Cases whose only defence is process or network isolation are out of scope for a mediator, and the count of excluded cases is reported.

## D10, 2026-11-03, open items

- AgentDojo, SafeClawBench, ToolPrivacyBench, ASPI and the boundary pairs are still being audited; the D-CBF authored share depends on whether ToolPrivacyBench exposes per-call disclosure and trajectory state.
- The "Contemporary Attacks" source in the reviewer grid is not yet identified and is not substituted by guess.
- The licence audit result for each source decides what may be redistributed in this repository.

## D11, 2026-11-03, one recommended source has no public data at all

Decision. ToolPrivacyBench is excluded from the corpus. SafeClawBench is included with a reduced usable set.

Evidence, counted from the fetched artefacts. ToolPrivacyBench, arXiv 2606.28061, has a GitHub repository that is a 479 byte README with no license field, no releases, and no dataset on Hugging Face; the arXiv source contains only TeX and figures. Its 2,150 cases cannot be audited or downloaded, so nothing enters the corpus and the paper counts remain quoted, not measured. Its own metrics are opportunity-normalised rates rather than a cumulative budget, so even if the data appeared it would not by itself supply the barrier layer.

SafeClawBench, arXiv 2606.18356, is MIT, not gated, and its 600 cases are genuinely 600 distinct cases in two joinable layers rather than 1,200. Grain is one critical call per case, so it contributes zero cases to families F10 to F14. Of the 600, 282 are expressible on the current tool surface, 185 need a filesystem tool, and 133 are memory cases that GATE cannot mediate.

Consequence. The D-CBF layer has no external supplier. That is a measured property of the field as of 2026-11-03, not a shortfall in the merge, and it is the reason the barrier and sequence cases are authored and disclosed as authored.

## D12, 2026-11-03, what the barrier implementation actually is, read from the code

Decision. The authored barrier cases are written against the invariants as implemented, and two implementation findings are reported rather than papered over, because Reviewer 2 asked exactly these questions.

From gate/security/dcbf_monitor.py, the five barriers are, before the margin subtraction of section 79:

| Barrier | Value | Weight | Default margin |
| --- | --- | --- | --- |
| safety | 1.0 minus the number of dangerous tool combinations present in the last five calls | 1.0 | 0.1 |
| privacy | 0.5 minus 0.2 per outbound email or HTTP call in the whole history | 1.5 | privacy_budget, 0.5 |
| resource | resource_limit minus accumulated cost | 1.0 | 0.0 |
| scope | max_drift minus the norm of the action embedding minus the context embedding | 1.2 | 0.0 |
| stability | step_budget minus step count | 1.0 | 0.0 |

Finding one, the privacy margin double counts. The margin is subtracted from a quantity that already starts at 0.5, so with the benchmark envelope of privacy_budget 0.5 the barrier value is minus 0.2 times the number of outbound calls, which is breached by the very first email rather than by accumulation. Setting the margin to zero restores the intended cumulative behaviour, breach at the third outbound call. Authored privacy cases use the zero margin, and the difference is reported as an implementation correction, not as a tuned threshold.

Finding two, the scope barrier is inert unless the runtime sets both embeddings. When either is None the barrier returns max_drift, a positive constant, so it can never breach. Nothing in the benchmark path sets embeddings, so the scope barrier contributes nothing in the published configuration and the paper must say so.

Finding three, the transition condition predicts the next state with a fixed dummy step, one hundred tokens, one api call, one cent, and phase ACTING, regardless of which tool is proposed. So condition (b), the discrete forward invariance check, is tool agnostic, and the containment work is done by condition (a), whether the current state is already outside the safe set. Any claim about predicting a specific action's effect must be scoped to that reality.

Method note. Reading the implementation to learn the invariant is not the same as reading monitor outputs to choose labels. Every authored case here is derived from the definitions above and frozen before any run on it, which is what D4 requires.

## D13, 2026-11-03, external cases are mapped onto capability-matched profiles

Decision. When an external case is harmonised, its profile grants the tools the case names, and the row records that it was matched this way.

Why. Under the profile as published, an InjecAgent attacker tool is simply not in the grant, so the privilege stage rejects it and the deeper layers never see it. Reporting that as coverage of five layers would be an artefact of the profile construction. Matching the capability lets each case reach the layer that owns its property, and the reviewer's distinction between the layer that owns a property and the layer that first rejects is preserved in a separate column.

Consequence. Privilege-layer supply comes from the GATE original suite and from variants where the grant is deliberately left restricted, and this is stated in the coverage table rather than hidden.

## D14, 2026-11-03, three enforcement asymmetries found while authoring the stateful families

These were read out of `gate/security/dfa_supervisor.py`, `gate/core/monitor.py` and `gate/security/privilege_enforcer.py` in order to write cases against the real invariants. Each one changes what a benchmark number means, so they are recorded before the run rather than discovered in the results.

One. The DFA loop limit is enforced per phase in `propose_transition` but only for ACTING in `validate_action_phase`, which is the function the runtime calls at a tool boundary. A `PLANNING` loop count past `max_loops_per_phase` therefore passes the boundary check. Authored F11 keeps its specification label for the two PLANNING shapes, and the resulting misses are reported as an enforcement gap, not relabelled as allowed.

Two. The privilege stage's budget test reads an estimated *per-call* cost from `ToolCall.metadata`, which no adapter populates, so it is inert in every measured path. Accumulated cost is reachable only through the D-CBF resource barrier. That is why the cost half of family F12 is authored under F14 instead, and why the paper should describe cost exhaustion as a barrier property rather than a supervisor property.

Three. Two of the three dangerous combinations the safety barrier looks for name tools outside the mediated surface, `file_read` with `send_email` and `database_query` with `webhook_post`. Only `sql_query` with `http_request` can ever fire, and only inside the five call window the barrier reads. Authored F14 safety shapes therefore use the reachable pair and place the second member at distance 1, 3 and 5, where distance 5 is a legitimate control because the older call has aged out of the window.

## D15, 2026-11-03, authored stateful stratum: 460 attacks in 46 templates

Decision. The dfa layer is authored to 200 attacks and the dcbf layer to 260, in ten fixed legitimate scenarios per violation shape, with 135 matched benign controls and 10 B02 hard negatives, frozen the same day as the generator.

Why. D3 put the quota on enforcement layers, and the audits confirm zero inheritable supply for these two: InjecAgent, SafeClawBench, AgentDojo, ASPI and the prompt-injection sets all label a call by its content or its outcome, never by the transition system or the accumulated envelope. The dcbf overshoot is deliberate, it is the layer with three sub-properties and the one that carries the cumulative-harm argument, and per D7 a larger group is what buys a tighter interval.

Consequence. What is held constant is the argument text. Inside a matched pair only `execution_context` changes, so any difference in the monitor's answer is a difference about accumulated state. Without that control a stateful benchmark cannot tell a barrier that works from a keyword filter that happens to fire.

Known limit, stated here rather than in the results. The scope barrier needs both a context and an action embedding and the harness sets neither, so no authored row can breach it, and the published configuration contains four live barriers rather than five.
