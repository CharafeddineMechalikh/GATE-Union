# AgentDojo audit — GATE-Union source 2 of 6

Audited 2026-11-03. Pinned artefact: official repo `https://github.com/ethz-spylab/agentdojo`
clone at HEAD `089ed468cf3ed0322acc66b0211f26d9d90dbf60` (2026-06-02, tag `v0.1.35` + 5 commits),
plus the PyPI sdist `agentdojo==0.1.35` (sha256 `9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956`,
hash verified). Raw copies in `external/raw/agentdojo/repo/` and `external/raw/agentdojo/pypi/`.
Note the historically referenced URLs `github.com/eth-zurich/AgentDojo` and `github.com/spylab/AgentDojo`
are dead; the org name is `ethz-spylab`. Introspection ran in an isolated venv
(`external/raw/agentdojo/.venv`, `pip install agentdojo==0.1.35 jsonschema`); the pinned shared
environment was not modified. NeurIPS 2024 Datasets & Benchmarks track (peer reviewed).

## 2. Counted numbers (measured on the artefact, not quoted)

The published claim (97 user tasks, 629 security test cases) **reproduces exactly** at
benchmark version `v1` of the fetched 0.1.35 package. Counting method: programmatic
introspection of `TaskSuite.user_tasks` / `TaskSuite.injection_tasks` filtered to each
`benchmark_version`, and the (user task × injection task) grid that
`benchmark.py::run_task_with_injection_tasks` actually runs.

| Environment | User tasks (v1) | Injection tasks (v1) | Security pairs (v1) | Tools |
| --- | --- | --- | --- | --- |
| workspace | 40 | 6 | 240 | 24 |
| travel | 20 | 7 | 140 | 28 |
| banking | 16 | 9 | 144 | 11 |
| slack | 21 | 5 | 105 | 11 |
| **Total** | **97** | **27** | **629** | 74 slots / 69 distinct names |

The four environment names are **banking, slack, travel, workspace** (the audit brief's
"workspace, Slack-like bank?" is imprecise; slack is a real fourth environment, banking is
not Slack-like). Caveats found:

- The 629 grid counts every user-task × injection-task pair per environment; only pairs whose
  injection vector actually surfaces in the task's ground-truth trajectory get a *content*-based
  injection (`BaseAttack.get_injection_candidates` canary check), but the benchmark still runs the
  full grid because vectors are shared across a mailbox/filesystem surface.
- Version drift: the base `default_suites/v1/*.py` files alone define only 33 workspace and 17 slack
  user tasks; later `v1_1_1`/`v1_1_2`/`v1_2_1` files repair/add definitions and `register_user_task`
  stamps them at version (1,0,0), so today's "v1" equals the paper's 97. At the current release
  (`v1.2.2`) the same 97 tasks combine with 35 injection tasks (workspace 6→14) into **949** pairs.
  Every harmonised row must record which benchmark_version it was counted from.

## 3. Licence and redistribution

MIT (repo `LICENSE`, © 2024 Debenedetti, Zhang, Balunovic, Beurer-Kellner, Fischer, Tramèr).
Verdict: **allowed_with_attribution** — cases may be committed to `harmonized/` provided the
MIT notice is preserved; `external/raw/` stays gitignored either way. **gated = false**: all task
data ships inside the package (`src/agentdojo/data/suites/<env>/environment.yaml`,
`injection_vectors.yaml`); there is no HuggingFace dataset and no access approval. Precomputed
model runs are also bundled (`runs/`), useful for baseline cross-checks.

## 4. Integration questions

**Execution and interception.** The stack is a `BasePipelineElement` chain
(`agent_pipeline/agent_pipeline.py`), not an OpenAI-assistant runtime. Mock backends are pydantic
`TaskEnvironment` state machines (e.g. `BankingEnvironment(bank_account, filesystem, user_account)`);
tools are plain functions with typed, docstring-derived Pydantic input schemas (`make_function`),
executed by `FunctionsRuntime.run_function` (`functions_runtime.py` L246), which validates args,
injects `Depends`-style env dependencies, then mutates the environment object.

- **Yes, a third-party monitor can intercept every tool call before it reaches the mock backend.**
  Exact extension points, in order of preference:
  1. **`BasePipelineElement.query` subclass placed before `ToolsExecutor` inside `ToolsExecutionLoop(elements=[...])`**
     (`agent_pipeline/base_pipeline_element.py` L8-37, `agent_pipeline/tool_execution.py` L46 and L118).
     The element sees the last assistant message's `tool_calls` (function name + args) pre-execution;
     it can withhold by not calling the executor, appending a refusal `role=tool` message, or raising
     `AbortAgentError`. This is the documented defense hook (`docs/concepts/agent_pipeline.md`:
     "You can also place defense components in the `ToolsExecutionLoop`").
  2. **`TaskSuite.run_task_with_pipeline(..., runtime_class=type[FunctionsRuntime])`**
     (`task_suite/task_suite.py` L339-346): pass a `FunctionsRuntime` subclass overriding
     `run_function` — a single choke point through which every call passes, ideal for a monitor
     that must see (tool, args, prior-call history) together.
  There is **no `Middleware`/`before_tool_call` API** in 0.1.35 (that was a pre-0.1.0 design; no
  such symbol exists anywhere in the package or its tags). The shipped
  `PromptInjectionDetector` / `TransformersBasedPIDetector` (`agent_pipeline/pi_detector.py`) are
  *post-execution* output scanners — they demonstrate the element API but are not by themselves a
  pre-execution gate.

**Security case structure.** One case = a `BaseInjectionTask` (`base_tasks.py` L97-160) with
`GOAL` (natural-language attacker instruction), `ground_truth()` returning the exact `FunctionCall`s
that constitute success (with `placeholder_args`), and `security()` / `security_from_traces()`
deciding success by deep-diffing pre/post `TaskEnvironment` state and scanning model output
(e.g. a transaction to attacker IBAN `US133000000121212121212` exists; the mailbox body appears in
an outgoing email). The attacker text is a jailbreak template from `attacks/` (8
`important_instructions` variants incl. `tool_knowledge` with substituted command templates, plus
`direct`, `ignore_previous`, `system_message`, `injec_agent`, and 5 DoS variants) rendered into
**injection-vector placeholders** declared per environment in `data/suites/<env>/injection_vectors.yaml`
(e.g. `injection_bill_text`, `email_password_reset_injection`, `injection_dora_0`) and embedded in
`environment.yaml` content — email bodies, drive files, transaction subjects, calendar descriptions,
Slack messages, webpages. The injection therefore reaches the agent **only inside `role=tool`
message content** returned by mock tool outputs, which is exactly GATE's semantic-firewall trigger site.

**Utility scoring (the anti-"block-everything" mechanism).** Independent of security, per user task:
`BaseUserTask.utility(model_output, pre_environment, post_environment, strict)` verifies the
*legitimate* objective by comparing the deep-copied pre/post environment (e.g. banking `user_task_0`
requires a transaction of exactly 98.70 to the bill IBAN) and/or that the final assistant answer
contains the expected content (`GROUND_TRUTH_OUTPUT`); read-only tasks use `utility_from_traces()`.
Utility is recorded on **every attacked run as well** — `SuiteResults.utility_results` is keyed by
(user_task, injection_task) — plus a clean utility-only mode (`run_task_without_injection_tasks`,
`attack=None`). A monitor that blocks all calls therefore keeps security ≈ 1 but collapses utility
toward 0, since legitimate side effects never land in `post_environment`. Attacker goals are
additionally executed as plain user tasks once (`injection_tasks_utility_results`) to prove each
goal is achievable in the environment at all. This is precisely the utility denominator SPEC §2 and
§9 need for benign controls; the 97 user tasks are its supply (51 fully expressible today — see §5).

## 5. Mapping onto the current GATE mediated tool surface

GATE surface: `admin_tool, code_execute, data_analysis, database_query, format_template,
http_request, send_email, sql_query`. Bucketing computed from the ground-truth `FunctionCall`s of
all 97 user tasks and 27 injection tasks (attack side = the call GATE must block; utility side =
the calls GATE must allow). Mapping judgment: all read/search/list tools → `database_query` (POI
discovery in travel → `web_search`); `send_email` → `send_email`; `get_webpage`/`post_webpage` →
`http_request`; account/user management (`update_password`, `update_user_info`, slack
invite/remove/add-channel) and destructive deletes (`delete_email`, `delete_file`) → `admin_tool`.

- **Directly expressible both sides: 208 / 629 pairs** (workspace 110, travel 60, banking 6, slack 32).
- **Attack-side call expressible (degrade-to-single-call candidates): 380 pairs**; the 172 extra
  pairs have a mappable attacker call but an un-mappable legitimate trajectory (must be excluded
  from F10–F14 per SPEC §5).
- **Not expressible even degraded: 249 pairs** (attacker call itself needs a new tool).
- Drop reasons over the 421 non-mappable pairs: payment/transfer tool missing 138 (128 attack-side —
  `send_money`, `schedule_transaction`, `update_scheduled_transaction`; effectively the whole banking
  exfiltration family), calendar-write tool 126 (60 attack-side), messaging-send 73 (21 attack-side:
  `send_direct_message`, `send_channel_message`), booking/reservation 44 (40 attack-side:
  `reserve_hotel/restaurant/car_rental`), filesystem-write 40 (utility-side `create_file`,
  `append_to_file`, `share_file`).
- Benign controls: 51 / 97 user tasks fully expressible today.
- Provisional family supply (pair-level, pre-dedup): F06 342, F04 101, F05 73, F07 40, F15 20,
  F02 16, F13 16 (the $30k-in-increments structuring injection), F16 21; no F01/F03/F08–F12/F14/F17
  supply; +97 B01. Layer supply: contracts 455, semantic 121, privilege 37, dcbf 16, dfa 0.
  AgentDojo is the expected external leader for F06 and the main benign/utility control supplier,
  but it adds nothing to dfa-family coverage.

**Verdict.** Usable without legal or access friction and technically friendly to GATE (two clean
pre-execution hooks). Real cost: to exceed the 208/629 expressibility share the surface must gain
payment, calendar, messaging-send and booking tools (SPEC §14 gap made concrete), or we accept
the 172-pair degraded single-call subset and report the exclusion.
