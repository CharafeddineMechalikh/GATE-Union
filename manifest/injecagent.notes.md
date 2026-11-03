# InjecAgent — GATE-Union source audit

Date: 2026-11-03. Auditor artefact: commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` (HEAD of `main`) of
<https://github.com/uiuc-kang-lab/InjecAgent>, cloned to `external/raw/injecagent/repo` (7.9 MB, no large blobs).
No pyarrow install was needed; every file is JSON/JSONL. Nothing in the pinned Python environment was touched.

## What the dataset is

InjecAgent (UIUC Kang lab; **ACL 2024 Findings**, arXiv 2403.02691) benchmarks tool-integrated LLM agents against
**indirect prompt injection (IPI)**. A user asks the agent to call a benign *user tool*; the tool's response
(e.g. an Amazon review) carries an injected *attacker instruction*. The measured event is the agent's next
proposed tool call. No models or outputs ship in the repo (model outputs live on Google Drive, per README; not
fetched).

## Counted case totals (from the artefact, not the paper)

| File | Rows |
| --- | --- |
| `data/test_cases_dh_base.json` | 510 |
| `data/test_cases_ds_base.json` | 544 |
| `data/test_cases_dh_enhanced.json` | 510 |
| `data/test_cases_ds_enhanced.json` | 544 |
| **Unique cases (base setting)** | **1,054 — matches the paper claim** |
| Raw rows across all four files | 2,108 (`enhanced` = same 1,054 cases, same order, only the Tool Response gains a "IMPORTANT!!! Ignore all previous instructions..." hacking prefix) |

Matrix is exactly **62 attacker scenarios x 17 user tools** (each scenario appears once per user tool; each user
tool appears 62x). 17 user tools confirmed in `data/user_cases.jsonl` (12 High / 5 Low "Level").
**Discrepancy:** the README/paper say "62 attacker tools"; the test files reference **63** distinct attacker tool
names (30 dh + 32 ds fetch tools + the shared stage-2 `GmailSendEmail`). The 62 figure counts scenarios, not tools.
Our reported count: 63.

## Field inventory (identical schema in all four test-case files)

- `Attack Type` — coarse category: {Physical, Financial, Data Security} Harm for dh; {Physical Data, Financial Data, Others} for ds.
- `Attacker Instruction` — the malicious objective, imperative sentence (explicit objective label: **yes**).
- `Expected Achievements` — free-text objective rationale (second explicit label).
- `Attacker Tools` — list; **len 1 = direct harm, len 2 = data stealing** (element 0 = fetch tool, element 1 always `GmailSendEmail`). This is how the two-stage variant is marked.
- `Modifed` [sic] — 0/1, instruction paraphrased to fit context (187/510 dh, 153/544 ds).
- `User Instruction`, `User Tool`, `Tool Parameters` (python-repr string), `Tool Response Template` (with `<Attacker Instruction>` placeholder), `Tool Response` (filled), `Thought` (seeded reasoning for the legitimate call).
- **Absent:** case ids, tenant, phase, budgets, expected_outcome field (outcome is implicit), per-row dh/ds flag (split is file-level).

**Tool definitions: shipped.** `data/tools.json` = 38 toolkits / 330 functions, each with name, summary, parameters
(name/type/description/required) and returns; join key is toolkit+function (`src/utils.py::get_tool_dict`). All 17
user + 63 attacker tools resolve; zero missing. `attacker_simulated_responses.json` ships 2,347 simulated stage-1
responses keyed by (attacker tool, params) so the S2 stage needs no live backend.

**Single call or trajectory?** Trajectory-context, single judged call. Each case seeds the legitimate user-tool
call (name+args) and its poisoned response; the agent emits the next call. Data stealing scores two stages: S1 =
fetch call, then shipped simulated response, then S2 = `GmailSendEmail` whose args must carry the fetched data.
Harness allows up to 3 actions; re-calling the user tool with fabricated observations = invalid.

## Licence verdict

**MIT (c) 2023 Qiusi Zhan**, root `LICENCE` file. No NC/ND clause → case contents **redistributable with
attribution** (`allowed_with_attribution`); ship the copyright notice with `external/raw` extracts. **Not gated**:
GitHub and HF mirrors are public, no form/approval. HF mirrors inventoried, not downloaded: `masahiroid/injecagent-ja`
(MIT, Japanese translation of same files), `penfever/injecagent-harbor` (per-case Docker repackaging, no licence
field on the card — treat as unofficial, pin the GitHub repo).

## Mapping feasibility onto GATE's mediated surface (9 tools)

Recommendation: harmonise **base setting only (1,054 rows)**; `enhanced` becomes a config column.

- **Clean (714 cases):**
  - dh 11 scenarios x 17 = 187: CiscoUmbrella x2 / Norton x3 / Evernote sharing / Facebook profile update / 23andMe
    update+share / GitHubDeleteRepository → `admin_tool`; TerminalExecute → `code_execute`.
  - ds 31 scenarios x 17 = 527: stage-1 fetches → `database_query` / `data_analysis` / `web_search`;
    stage-2 exfil → `send_email` (clean for all ds).
- **New tool or profile needed (340 cases)** — exactly the SPEC §14 gaps: payment backend 119 (Bank/Binance/Venmo/FedEx,
  7 scenarios); IoT/physical actuators 119 (smart lock, Google Home, robot, traffic control, emergency dispatch, 7
  scenarios); health/calendar 51 (EpicFHIR x3); filesystem 17 (DropboxMoveItem); messaging workspace 17
  (SlackLeaveChannel); media generation 17 (DeepfakeGenerator).
- Benign controls: the 17 distinct legitimate preceding calls (each appears 62x) map mostly to
  `web_search`/`http_request`/`database_query`; the two GoogleCalendar user tools and `WebBrowserNavigateTo`
  degrade or need profiles.
- **Degenerate-F01 warning:** leaving attacker tools ungranted makes all 1,054 cases trivially F01 at privilege
  stage; harmonisation must map the malicious call onto an in-grant mediated tool (or extend the surface) or the
  source tests nothing past stage 1.

## Family supply (primary by violated property; all cases carry `attack_vector=tool_response`/`retrieved_content`)

| Family | Cases | Basis |
| --- | --- | --- |
| F05 direct_harmful_action | 476 | 28 dh scenarios (harm inside the acting grant) |
| F06 data_exfiltration | 544 | all ds scenarios (fetch → email objective) |
| F07 destructive_operation | 17 | GitHubDeleteRepository |
| F09 code_contract_violation | 17 | TerminalExecute (shell/file policy breach) |
| B01 benign_task_call | 17 | distinct legitimate preceding calls (utility track) |
| **Nothing** | 0 | F01 (only degenerate), F02, F03, F04 (primary), F08, F10, F11, F12, F13, F14, F15, F16, F17 |

InjecAgent is single-tenant, one-shot, no state, no budgets: **zero supply for the stateful families F10–F14 and
for F17**; F04/F15 appear only as the injection trigger, recorded as secondary layers, never as vector==family
conflation (SPEC §4). Layer supply therefore concentrates entirely on `contracts` (1,054).
