# ToolPrivacyBench — acquisition audit notes

Audited 2026-11-03. Audit record: `manifest/toolprivacybench.audit.json`. Raw files: `external/raw/toolprivacybench/`.

## 1. Headline verdict

**The benchmark data is not publicly available.** There is nothing to fetch, so `cases_upstream` is recorded as **0** rather than guessed, and no case from this source may enter `harmonized/`. This is stated plainly instead of substituting a stand-in dataset.

## 2. What exists, pinned

| Artefact | Pin | Contents |
| --- | --- | --- |
| Paper | arXiv:2606.28061v1, submitted 2026-06-26, cs.CR primary + cs.AI, 24 pages / 7 figures / 15 tables. No v2 or v3 (`abs/…v2` and `v3` return HTTP 404). No journal-ref, no venue DOI. | `arxiv_abs_2606.28061.html`, `arxiv_html_2606.28061.html`, plain-text extraction `arxiv_2606.28061.txt` (sha256 `ce164bff…c738`) |
| Official repo | `HuShijing123/ToolPrivacyBench`, commit **`51d13355a8cb78d80c45b756dd347e94c40327e6`**, `main`, 2026-06-27T08:56:24Z, **2 commits, 2 KB, 0 stars, no releases (empty array), no other branch** | one blob: `README.md` (479 bytes, blob sha `508dce6a20eb875807365053ec39d64f0a072a3f`) — `github_README.md` |
| arXiv source tarball | sha256 `91daadc6…897be`, 1,466,607 bytes | `main.tex` 121,248 B, `references.bib`, `elsarticle.cls/.bst`, `00README.json`, 8 figure PDFs. **No data file, no case JSON, no code.** — `arxiv_src_2606.28061` |
| Hugging Face | — | **does not exist.** `/api/datasets` searches for `toolprivacy`, `ToolPrivacyBench`, `privacybench`, `need-to-know disclosure` → no match; `author=HuShijing123` and `author=hushijing` → `[]` |

The repository README, verbatim: "This repository is currently a placeholder. Code, benchmark data, evaluation scripts, and documentation will be made available after the publication process permits public release." The paper is future tense too: "The code and full benchmark data **will be** released". A whole-text search of `main.tex` for `github` / `huggingface` / `url` / "available at" returns only those two release sentences — **the paper carries no artefact URL.** No Zenodo record, no arXiv supplementary zip.

**Status: preprint, unreleased data. Not peer-reviewed.** Licence: the repo has no LICENSE file and GitHub reports `license=null`; only the manuscript is licensed (arXiv perpetual non-exclusive). **Redistribution verdict: `unknown`** — there is neither data nor licence grant.

## 3. Counts quoted from the paper (never a denominator)

2,150 cases = 1,150 synthetic Need-to-Know workflows + 1,000 public-derived. Table 5: 23 vs 16 domains, 552 vs 258 tools, 6.00 vs 8.89 tools/case, 7.00 vs 12.77 atoms/case, 8,050 vs 12,767 private atoms, 80,040 vs 139,946 field–tool pairs, 45,170 vs 44,472 authorized and 34,870 vs 95,474 forbidden; text totals 20,817 atoms and 219,986 pairs. Exactly **one** concrete case id appears in the whole paper (`coding_000151`). Annotation reliability is sampled only: 215 cases, 21,994 pairs, raw agreement 93.1 %, Cohen's kappa **0.86**, 499 adjudicated changes — the authors note this "does not imply that the full benchmark was independently re-annotated". Evaluated agents are nine commercial endpoints (GPT-5.5, Claude Opus 4.7, DeepSeek V4 Flash, Kimi K2.5, GLM 5.1, Qwen3.6-plus, Gemini 3.5 Flash, Doubao Seed 2.0 Lite, MiniMax/GLM family), unpinned by version.

## 4. The three privacy-budget fields — what is recoverable

| Needed for GATE | Designed? | Recoverable today? | Where it would live |
| --- | --- | --- | --- |
| **Per-tool authorised information set** | **Yes, fully specified.** Case `c=(x, T, P, A)`: task, tools with `t_i=(name, purpose, schema, sink)`, private atoms `P`, and the **field–tool authorization matrix A** (rows = atoms, columns = tools/sinks, cell = authorized/forbidden), plus severity weights `w_j > 0` per atom. Projected from the policy knowledge base. | **No** — no machine-readable A is published anywhere. | This is exactly our smart-contract object: a per-call, per-argument allow-list rather than a per-tool capability. |
| **Disclosure made by each call** | **Yes.** Trajectory `tau = ((t_1,a_1)…(t_K,a_K))` recorded by mock backends into audit logs; a Disclosure Detector computes `D(p_j, a_k)` over structured arguments and `D_text(p_j, a_k)` over free-text slots (`note`, `message`, `description`, `summary`, `work_notes`); an Authorization Reasoner intersects detected pairs with the forbidden cells (Table 4 module I/O). | **No** — no trajectory, no audit log, no atom list shipped. | Also inherits the detector's sampled reliability; free-text atom matching is the weakest link (FreeTextFOR 27.16–46.76 on the synthetic split). |
| **Cumulative privacy budget over a trajectory** | **Not as a budget. This is the substantive negative finding.** | **No**, and even after release the quantity would be **ours** to define. | Every trajectory metric is a **rate normalised by opportunity count**, not an accumulated amount against a limit: FOR = Σ_k Σ_j D·1[A_j,i(k)=0] / Σ_k Σ_j 1[A=0]; SWLR weights it by `w_j`; ToolFOR restricts to one tool; LTCR = mean of the per-step binary leaky-call indicator `L_k`; MidFOR separates mid-workflow from final-answer leakage; MT-POI = 100·(0.2 FOR + 0.2 SWLR + 0.2 ToolFOR + 0.2 FreeTextFOR + 0.2 MidFOR); SMTC = 100·TaskSuccess·(1 − MT-POI/100). |

So: the **inputs** for cumulative accounting are all defined — per-atom authorised set, per-step realised disclosure, per-atom severity, step index. What is missing for our D-CBF barrier is the **budget itself**: no epsilon, no per-atom or per-sink quota, no running-sum-against-threshold, no monotone drift or inverse-barrier condition, no safe envelope. Worse, the policy knowledge base is explicitly post-hoc — "not provided to the baseline agent as an execution-time defense; it is used only after task completion for auditing". That is the mirror image of GATE: they audit a finished trajectory, we must decide at the call.

**Consequence for the manuscript:** any F13 case "derived from ToolPrivacyBench" would in fact be an authored policy decision wearing external clothing. Per SPEC 10, 13 and 15 it must be reported as authored, with the authored share stated, or F13 must fall back to the GATE-original `dcbf_privacy` cases with the external gap disclosed.

## 5. Grain, and why we still wanted it

Cases are genuine **trajectories**: each retained public-derived case must have ≥4 source tool calls, ≥2 distinct tools, ≥4 sensitive atoms, ≥2 free-text-capable tools and ≥20 forbidden field–tool opportunities (6.00 and 8.89 tools/case). The failure mode is **non-adversarial by design** — the user request is benign, no attacker modifies prompt, model, tools, policy or log — so the whole corpus is `attack_vector = direct_user_request` with a privacy property. It would add nothing to F01/F02/F03/F10/F11/F12 and nothing to the injection vectors; its value is exclusively F06/F08-style argument-level contracts plus the trajectory privacy property.

## 6. Mapping onto GATE's mediated surface

No case can be mapped (0 fetched), so `family_supply` and `layer_supply` are zeros. Design-level assessment of a future release, **projected, not measured**:

- Tool names are published only as paper examples (Table 3: `medical_verify_identity(name, phone, patient_id)`, `medical_process_payment(case_id, amount, insurance_type, card_suffix, note)`, `medical_notify_patient(phone, message)`, `medical_team_handoff(case_id, status, next_action, summary, work_notes)`) plus Table 2 domain chains.
- Coarse fit against our nine: notification/handoff → `send_email` (same egress shape, wrong recipient model); record/ticket/claim creation → `database_query`/`sql_query` (**poor** — ours takes a query string, not a named field map, so atom-to-field attribution is lost); document/summary generation → `format_template` (best fit for free-text slots); verification/lookup → `database_query`; payment, dispute, upload → **no fit**; risk/income aggregation, deduction review → `data_analysis`, no fit as specified.
- **The blocking gap is policy granularity, not the tool list.** Our privilege and contract stages reason over tool name, coarse argument values, roles, tenants and budgets; SPEC 5's `tool_arguments` is an untyped map with no field-level authorization annotation. Required additions: (i) an argument-field authorization table per mediated tool — a contracts-schema change and therefore a SPEC 17 version bump; (ii) a sink model distinguishing structured field from free-text slot; (iii) a per-trajectory accumulated-disclosure ledger with a budget and threshold in `execution_context`, which nothing upstream supplies; (iv) business egress tools (notify, ticket, handoff, payment) or a documented many-to-one collapse onto `send_email`/`http_request`/`format_template` with the loss recorded.
- Proportional projection for 2,150 cases if released: ~45–55 % (≈950–1,200) argument-level on a mappable sink; ~35–45 % (≈750–950) state-mutating record/ticket writes needing a new business-record tool; ~10 % (≈200) payment/upload/aggregation calls with no current fit. Cannot be tightened before the data exists.

## 7. Recommendation

Keep `toolprivacybench` in the source table as **announced, unreleased**, with the quoted 2,150 never entering a denominator. Re-check for a release before submission; if it appears, re-pin at a commit sha and then verify the licences of **τ-bench, API-Bank, BFCL and AppWorld**, whose derived cases would inherit upstream terms through the derivation chain — that check was out of scope here and was not performed. The coverage table should show F13 as a documented external shortfall, which is itself a finding about the field rather than about our monitor.
