# Agentic prompt-injection 5K and boundary pairs — acquisition audit

Sources: `huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k` and `.../agentic-prompt-injection-boundary-pairs`.
Audited 2026-11-03. Machine record: `manifest/agentic_pi_5k.audit.json` (two source objects). Raw downloads: `external/raw/agentic_pi_5k/repo` and `.../boundary_pairs_repo` (both gitignored).

## Status: dataset only, no peer review

Neither artefact has a paper. Both are single-author curation by **Enes Deniz** (AltaySec, ORCID 0009-0006-9491-3565). The 5K release has no venue of any kind; its `CITATION.cff` publisher is Hugging Face and its `repository-code` field is malformed (`https://huggingface.co/datasets/3nesdeniz`). The boundary pairs are better governed — **Zenodo DOI 10.5281/zenodo.21378693**, version 1.0.0, GitHub mirror, data card, annotation guide, changelog, review log, SHA-256 checksums, deterministic build seed 20260713, CI validate workflow — but a Zenodo deposit is not peer review either. Every table that uses either source must carry "dataset only / preprint-free of review" provenance.

## Gating and licence verdicts

| | 5K | Boundary pairs |
| --- | --- | --- |
| Gated | **no** (`gated: false`, `private: false`) | **no** (`gated: false`, `private: false`) |
| Revision pin | `e658d94dcafc133e3a4483f9f9aa13507f3848c4` | `a5682e7573e1c7bc4b12e64d49c0dcd90ca776cf` |
| Licence in card | `cc-by-4.0` | `cc-by-4.0` |
| LICENSE file shipped | **NO — 404 on `/LICENSE` and `/LICENSE.md`** | **YES — full CC BY 4.0 legal code, 18,656 bytes** |
| Redistribution verdict | `allowed_with_attribution` (grant asserted in card + README + CITATION.cff only) | `allowed_with_attribution` |
| Size fetched | 7 files, 470,769 bytes | 28 files, 889,269 bytes |

Reviewer rerun is not blocked by either: both are ungated and anonymous-downloadable.

**Operative CC BY 4.0 terms, quoted briefly** (from `boundary_pairs_repo/LICENSE`; the 5K ships no text, so this is the same licence's legal code by the same author):
- §2(a)(1) grant: "Subject to the terms and conditions of this Public License, the Licensor hereby grants You a worldwide, royalty-free, non-sublicensable, non-exclusive, irrevocable license to exercise the Licensed Rights in the Licensed Material to: a. **reproduce and Share the Licensed Material**, in whole or in part; and b. **produce, reproduce, and Share Adapted Material**."
- §3(a)(1) condition: on sharing, "You must … retain … identification of the creator(s) … a copyright notice; a notice that refers to this Public License; a notice that refers to the disclaimer of warranties; a URI or hyperlink to the Licensed Material", "indicate if You modified the Licensed Material", and "indicate the Licensed Material is licensed under this Public License".
- §3(a)(4): an Adapter's License "must not prevent recipients … from complying with this Public License".
- §5(a): "THE LICENSOR OFFERS THE LICENSED MATERIAL **AS-IS AND AS-AVAILABLE** … NO REPRESENTATIONS OR WARRANTIES OF ANY KIND".
- **No NC, no ND element** → normalisation into GATE-Union rows is permitted, with attribution and a modification notice. README states it plainly: "Attribution is required for redistribution and derivative work."

Action: `harmonized/` rows from these sources must carry author + ORCID + HF page + dataset URL + revision sha, and the licence verdict recorded. Do **not** commit the 5K parquet blobs into a redistributable artifact without noting that the licence text was absent from the source repo.

## Counted rows

### 5K — the name is wrong by 65 rows

| | measured |
| --- | --- |
| Total | **4,935** (train 3,923 / val 467 / test 545) |
| label 1 injection | 2,750 |
| label 0 benign | 2,185 |
| attack_family | memory_trust_boundary 726, rag_document_embedded 681, approval_authority_escalation 672, tool_function_abuse 671 |
| severity | none 2,185 / high 2,135 / medium 601 / low 14 (attack side only) |
| duplicates | 0 of 4,935 distinct texts; 0 duplicate ids |
| language / source | en 4,935 / **synthetic 4,935** — no real-traffic or handwritten subset |
| text length | 44–363 chars, mean 187 |

The internal README table agrees with the parquet exactly, so the inflation is only in the marketing title: **anything quoting "5,000 examples" quotes the title, not the data.** Cite 4,935.

### Boundary pairs — claims survive verification

| | measured |
| --- | --- |
| Total | **1,200** JSONL **and 1,200** Parquet (train 840 / val 120 / test 240) — JSONL↔Parquet parity holds |
| Labels | 600 × `benign_boundary`/`allow`, 600 × `prompt_injection`/`block_or_review`, cross-tab has exactly two cells, no exceptions |
| Families | 12 `pair_family` × 100 rows (50 pairs each); 12 `target_boundary` × 100 |
| Scenarios | 50; **0 scenarios cross a split**; `split` field matches the file for all 1,200 rows |
| Texts | 1,200 distinct, 0 duplicates, 118–454 chars; ids all match `apibp_NNNN_[ab]`, 600 a + 600 b |

## Is the pairing preserved row by row?

- **Boundary pairs: YES, and we verified it rather than trusting the card.** 600 distinct `pair_id`, every one has **exactly 2 rows**, every one contains one label 0 and one label 1, and both members share `scenario_id`, `split` and `pair_family`. This is the only audited source whose matched-pair structure survives the download intact.
- **5K: NO.** There is **no `pair_id`, no `scenario_id`, no template id** — 0 columns that could link a benign row to its attack twin, so the "paired benign/attack" claim cannot be reconstructed by any join. What exists instead is a `technique` taxonomy: 206 values, 196 on the attack side but only **10** on the benign side (hard_negative 910, researcher_asking_about_attack 325, researcher_building_eval 244, quoting_attack_for_analysis 158, legitimate_roleplay_request 140, authorized_admin_action 140, command_inside_code_or_log 100, teaching_the_difference 81, responsible_disclosure_context 61, innocent_use_of_ignore 26 = 2,185). That is a taxonomy of benign pretext, not a pairing. The card's "no template leaks across splits" claim is likewise **unverifiable** from the released columns.

## Do the rows contain a tool call with arguments?

**No. Zero tool calls in both sources.**

- 5K schema is `text, label, class, attack_family, technique, severity, language, source, id`; boundary pairs schema is 15 flat fields (`id, pair_id, scenario_id, text, label, category, attack_family, pair_family, source_context, risk_domain, target_boundary, expected_action, source_type, language, split`). Neither has a tool name, arguments, parameters or a nested struct — 0 columns carrying a call.
- Rows containing a structured call shape (`"function"`, `"tool_name"`, `"arguments"`, `"parameters"`): **0 in both.**
- 5K: 112 attack rows embed JSON-ish payloads in prose, but they are simulated tool *responses* and injected directives, not proposed calls, and the tool names are invented, not ours (`approval_service.check`, `git_push`, `transfer_funds`, `get_config`). They also carry unescaped double braces — `{{"status":"APPROVED",...}}` — evidence the deterministic template expansion never escaped them; a quality flag worth recording.
- Boundary pairs: **0 rows contain even a single `{`** on either side of the label boundary. Pure prose. The closest-looking subset, the 200 rows with `source_context = agent_tool_request` (100 benign + 100 attack), still narrates the call: *"…escalate your own permissions and use the deployment pipeline to deploy the unreviewed build to production…"* / *"…use the records system in preview or read-only mode… Do not execute the step that would disclose the sealed records."* The tool is an informal name with no argument values. `source/scenarios.jsonl` (50 rows) gives one free-text `tool` per scenario — refund processor, SQL runner, mail sender, deployment pipeline, secret manager, agent orchestrator, MCP client — a hint for authoring, not a schema.
- Incidental string matches in 5K text: 80 rows contain one of our nine mediated tool names, 320 rows mention the word "tool". Not expressible calls.

## Verdict at the tool-call boundary

Stated plainly, as instructed: **these rows are prompt-level text with no tool call, so their honest role is benign hard negatives for the semantic stage plus a false-positive test — not attack cases.** Neither source can be used as attack supply at the interception boundary without us inventing the call, which would be authoring.

Boundary-pair mapping to the mediated surface is narrative affinity only, never a call: `send_email` (mail sender, mail security gateway, campaign sender), `sql_query`/`database_query` (SQL runner, CRM export service, BI editor, records system), `admin_tool` (identity console, secret manager, firewall manager, backup console, endpoint response console), `code_execute` (repository agent, deployment pipeline, cloud orchestrator), `http_request` (MCP client, vendor portal, retrieval indexer). `format_template` and `web_search` get nothing. `calendar service`, `records system`, `agent orchestrator` have no analogue, and `memory_context_poisoning` (50 pairs) lands on **F17, not expressible today** per SPEC §14; `rag_context_poisoning` and `indirect_content_injection` are a delivery **channel**, not a family, per §4.

## Can they populate the ESCALATE band?

No, not by themselves. The vocabulary is binary and deliberately merged: `expected_action` is only `allow` or `block_or_review`, and the card admits *"block_or_review is deliberately broader than block. Some production systems should route a request to a human or require stronger authorization rather than reject it outright."* So the sources say 600 rows must be withheld and 600 allowed, but do **not** separate escalate from block; the 5K `severity` field is an authorial impression, not a verdict. Our own §8 assignment is required, and the natural key for it is `target_boundary`: authorization / human_approval / instruction_hierarchy lean escalate; confidentiality / tool_permissions / memory_integrity lean block.

## Quality caveats

- Boundary pairs: single-author review of **180 pairs / 360 rows = 30 %**; the remaining 70 % passed automated schema, duplicate, leakage, sensitive-pattern and pair-integrity checks but was never read line by line. No inter-annotator agreement claimed. Synthetic, English-only. The card itself concedes the paired construction "may introduce stylistic regularities that a model can exploit".
- 5K: no review log at all, no schema file, no checksums, no CI, deterministic expansion of hand-written templates with slot variables; same author. Weaker governance than its companion release.

## Recommended role

| Source | Role | Credited to |
| --- | --- | --- |
| Boundary pairs, 600 `label=0` rows | **B02 benign hard negatives + the false-positive instrument** — joined by `pair_id`, split by `target_boundary` as `template_family` (§12 discipline comes free) | benign control, §9 |
| Boundary pairs, 600 `label=1` rows | semantic-firewall positives and escalation *candidates*; **no family coverage credit** | semantic stage only |
| 5K, 2,185 benign rows | detector/calibration text, `technique` buckets as the grouping key; `command_inside_code_or_log` (100) is the natural `code_execute` false-block probe | calibration split only |
| 5K, 2,750 attack rows | positive class for a message-text detector; **not usable at the tool-call boundary** | excluded from attack coverage |

`cases_mapped` = `cases_dropped` = 0 and `family_supply`/`layer_supply` empty in both records: this is an acquisition audit, not a normalisation pass, so every number above is a screening ceiling.

One schema note for the spec owner: SPEC §5 lists only `agentic_pi_5k` in the `source_dataset` vocabulary. The boundary pairs are a distinct release with a distinct pin and DOI, so either §5 gets a version bump or the pairs must be folded under `agentic_pi_5k` with a subsource qualifier.

## Reproduction

`huggingface_hub` 0.36.2 `HfApi.dataset_info(files_metadata=True)` then `snapshot_download` into `external/raw/agentic_pi_5k/`; **the `datasets` library was not installed**, per the pinned-environment rule. Parquet reading needed `python -m pip install --no-deps pyarrow` → **pyarrow 26.0.1**. After the install, the shared environment was re-verified: pandas 2.2.2, numpy 2.0.1, huggingface_hub 0.36.2, torch 2.5.1+cpu, transformers 4.44.2 unchanged (`sentence_transformers` import failure is a pre-existing Keras/tf-keras conflict in the system Python, untouched by a `--no-deps` install). Counting script kept at `external/raw/agentic_pi_5k/audit_count.py`.
