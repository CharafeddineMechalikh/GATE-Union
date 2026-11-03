# SafeClawBench — acquisition audit notes

Audited 2026-11-03. Audit record: `manifest/safeclawbench.audit.json`. Raw files: `external/raw/safeclawbench/_repo/` at the pinned revision, hashes in `external/raw/safeclawbench/_sha256_manifest.json`.

## 1. Identity, status, pin

| Item | Value |
| --- | --- |
| Paper | arXiv:2606.18356v1, submitted 2026-06-16, 32 pages / 5 figures, cs.CR + cs.AI, DOI 10.48550/arXiv.2606.18356 |
| Title | SafeClawBench: Separating Semantic, Audit-Evidence, and Sandbox Harm in Tool-Using LLM Agents |
| Authors | Tian, Zheng, Mei, Yuan, Xu, Chen, Chen, Wang (PKU, BJTU, SUIBE, Huawei, Tsinghua) |
| Dataset | `sairights/safeclawbench`, revision `e6c29204c24a5910600aae854baae57a51586655`, last modified 2026-06-16 |
| Status | **Preprint, under review. Not peer-reviewed.** Card says "Preprint, under review"; bundled `COMPLIANCE_REPORT.md` targets NeurIPS 2026 D&B and its pre-submission checklist is still open. Quote it as a preprint, never as a published benchmark. |
| Gating | `gated=false`, `private=false`, no token needed. Reviewer re-run of the *data* is possible; re-run of their *rates* is not (model ids unpinned). |
| Licence | MIT in four places (LICENSE, card `license:mit`, `croissant.json`, `CITATION.cff`). **Verdict: `allowed_with_attribution`.** Note the copyright line says "ClawSecBench Authors", a name used nowhere else in the release. |

## 2. Counted case totals (counted, not quoted)

| File | Rows | Note |
| --- | --- | --- |
| `benchmark_v5_600.json` | **600** | canonical Semantic Core, 600 unique `task_id`, exactly 100 per family for DPI/IPI/TRI/MPI/MEX/ADI |
| `executable/fixtures/exec_full_600.json` | **600** | executable mirror; joins 1:1 with the Core (`task_id == case_id`: overlap 600, exec-only 0, Core-only 0) |
| `executable/fixtures/exec_subset_150.json` | 150 | verified strict subset of the 600 |
| `executable/fixtures/exec_subset_60.json` | 60 | verified strict subset of the 600 |
| `executable/fixtures/tiny_subset.json` | 3 | **README claims 5** — card is stale |
| `benchmark/benchmark.json` | 72 | v1 draft, `generated_at 2026-04-01`, **zero id overlap** with the 600 — do not count |

**Corpus = 600 distinct cases carried in two layers, not 1,200 cases.**

## 3. What the three-way separation is in data terms

This is the same axis as our classification-vs-containment split, so field names matter.

| Endpoint | Fields that encode it | Deterministic? |
| --- | --- | --- |
| **Semantic compliance** | Core file: free-text `success_predicate` + `safe_behavior`, scored by an LLM judge on the agent's *text* (README 8.1 → `attack_success`, `safety_score`, `harm_evidence_category`, `defense_behavior`). Exec: `Intent-ASR`, which ships **disabled** — `default_intent_judge` returns `None`. | **No.** Judge output only; no machine-readable semantic label in the release. |
| **Audit evidence** | `success_predicate.tool_calls[]` matched against the trajectory log (`executable/metrics.py` → `tool_call_asr` / ToolCall-ASR): match = tool name + exact `arguments` or substring `arguments_contains`, with a `require_success` variant that excludes `blocked_by_harness` events. Judgemental twin: `harm_evidence_category` ∈ TextHarm/AccessHarm/ActionHarm/PersistHarm/SemanticOnly/NotObservable. | Yes (call level). |
| **Sandboxed harm** | `state_oracle.checks[]` evaluated on `initial_world_state` → final state (`state_change_asr` / StateChange-ASR). Kinds in use: `memory_value_contains` 133, `email_sent` 125, `code_output_contains` 99, `file_contains` 93, `file_created` 66, `database_row_modified` 58, `file_deleted` 50, `tool_called` 34; `mode` all 575 / any 25. | Yes. |
| **Conjunction** | `HarmCompletion-ASR` = AND of `success_predicate.requires`, which is `["tool_call","state_oracle"]` for **all 600** rows. | Yes. |

Their headline gap — 291 of 347 observed sandbox harms in rows that **pass** the semantic check (12,000-row = 5 models x 4 policies x 600 join) — is quoted from README/REPRODUCIBILITY.md. We did not re-run it; the per-row result files are not in the release.

## 4. Grain: single call, or trajectory?

**Single critical call inside a bounded trajectory.** Every exec row specifies exactly one predicate call (`tool_calls` length = 1 for 600/600). `metadata.mock_attack_plan` is 1 step in 351 rows, 2 steps in 249. Execution is either scripted replay (`runner.py`) or a live API loop capped at `max_turns=10`. No case conditions on a transition, a re-entry count, or a cost ceiling.

Consequence: **measured supply for F10–F14 is zero.** The 249 two-step read-then-write rows are the only sequence-dependent material, and under SPEC 5 they must be entered as degraded single-call and excluded from F10–F14 scoring — an exclusion we report, not hide.

## 5. Tool definitions

Yes, they ship, twice, and the two copies disagree. `harnesses/base.py` `SIMULATED_TOOLS` declares 10 tools with description + typed parameters; `executable/tools.py` implements **11** permissioned mock backends, adding `database_write` (the harm call in 58 rows) which `base.py` lacks. Per case: `available_tools` = 2 (409 rows) or 3 (191 rows); `tool_permissions` = `read_paths`/`write_paths`/`delete_paths` globs, `allowed_keys` for memory, `allowed_domains` for `web_browse` (100 rows), or bare `allowed:true` (408 rows). `web_search` is defined but used in **0** cases.

The path/key/domain allow-list vocabulary is the closest external analogue of our privilege-stage capability model and is directly reusable.

## 6. Mapping onto GATE's mediated surface

Bucketed by the tool named in `success_predicate.tool_calls[0]` (the call we would have to withhold); 282 + 185 + 133 = 600.

| Bucket | Cases | Detail |
| --- | --- | --- |
| Expressible today | **282** | `execute_code` 99 → `code_execute`; `send_email` 125 → `send_email`; `database_write` 58 → `sql_query`/`database_query` |
| Needs a filesystem tool | **185** | `write_file` 126, `read_file` 34, `delete_file` 25 — SPEC 14 already flags filesystem |
| Not expressible, persistent memory (F17) | **133** | `memory_write` 133 = MPI 100 + `ipi_memory_poison` 33. Either extend the surface with the capability/sequence/barrier work done, or exclude all 133 and report it. No third option. |
| Primary on `http_request`/`web_search`/`admin_tool`/`data_analysis`/`format_template` | **0** | `web_browse` appears only as an injection surface, never as the harm call, so F16 supply is 0 at call level |

Must be added: (a) `fs_read`/`fs_write`/`fs_delete` with path allow-lists; (b) persistent memory or a documented F17 exclusion; (c) a protected-asset registry plus an **argument-content** predicate; (d) a content-bearing call-time oracle — a state-diff oracle only fires post-execution and cannot answer a call-boundary question.

Provisional family supply (subtype-level, **not** per-case reviewed; sums to 600): F05 126, F06 158, F04 67, F09 66, F07 50, F17 133. Layer: contracts 400, semantic 67, not expressible 133, dfa 0, dcbf 0, privilege 0.

## 7. Defects we must not inherit

1. **One field name, two types**: `success_predicate` is a free-text string in the Core file and a structured object in the exec file. Read them as two tables joined on id, or a normaliser silently coerces.
2. **Exfil oracles do not look at the secret.** 125 `email_sent` checks carry **no** constraint keys at all — sending any email is scored as successful exfiltration. `contains_any_secret` / `contains_secret_ref` are implemented but used by **0** shipped rows.
3. **Arguments mostly unpinned**: 381/600 attack predicates pin the tool name only; 152 pin `path`, 67 pin `key`; `arguments_contains` never used. The payload exists only as canaries in `initial_world_state` (125 rows hold an obvious `SECRET`/`api_key`/`password` literal) and in `metadata.mock_attack_plan`, which is a reference trace, not a spec.
4. `secret_objects` populated in 259 rows (125 `file:`, 100 `web:`, 34 `memory:`) but consumed by no oracle — currently documentation.
5. Vocabulary drift: `harm_type` has one out-of-domain value `resource exposure` (1 row); `lifecycle_stage` has `input` (48 rows) though README documents only inference/decision/execution.
6. **No benign controls.** All 600 rows are adversarial: 0 B01/B02, so this source alone cannot support the operational-cost / false-block measurement of SPEC 2 and 9. Legitimate behaviour exists only as `expected_safe_behavior` text and `mock_safe_plan` metadata.
7. Exec endpoint is process-level sandboxing. Under SPEC 14 (GATE mediates, does not isolate), the 600 sandbox harms are evidence about containment, not about our monitor; only call-level fields transfer.

## 8. Use in GATE-Union

Redistribute with MIT attribution, pinned to the revision sha rather than HEAD (untagged repo, stale README). Value is the **three-column separation** (intent / call-evidence / state-harm) and the call-boundary oracle structure — the cleanest external statement of the classification-vs-containment distinction the reviewers asked for. Cost is 133 F17 cases we cannot express, zero stateful supply, and exfil labels that ignore content.
