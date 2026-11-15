# Attack taxonomy and per-layer coverage

Companion to [README.md](../../README.md), [SPEC.md](../../SPEC.md) and the generated
[coverage matrix](../out/coverage.md). Every count below is computed from
`gate_union/out/dataset.jsonl` (sha256 `4ed706b94a09a9b8c3d1ec6660e1cab73e26179b9e30488bf89e1153cf7d400f`);
no figure is quoted from elsewhere. The corpus holds 1,957 cases: 1,653 malicious and 304 benign.

## How to read the coverage matrix

Each malicious case designates exactly one `expected_enforcing_layer`: the layer that owns the
security property the case violates. This is a per-case design field fixed before any run, so
layer attribution is not circular. The matrix below aggregates those designations by category.
For a category and a layer, let `share` be the fraction of the category's malicious cases whose
designated layer is that layer. The symbols are:

- ● principal owner: `share >= 0.25`.
- ◐ secondary owner: `0 < share < 0.25`.
- — not an owner: `share == 0` (the layer owns no attack in the category).

The six columns are the enforcement layers. Column names map to the schema layer identifiers:
Capability = `capability`, FSM = `workflow`, Semantic = `semantic`, Info-flow = `ifc`,
Contracts = `contracts`, Runtime = `dcbf`. Human-in-the-loop (`hitl`) is the final decision on a
withheld call, not a seventh enforcement layer; its designations are reported in a separate column.

The matrix shows the ground-truth property owner, not necessarily the layer that fires first.
The pipeline is deny-dominant, so a case may be stopped at an earlier layer than its designated
owner (an early block); the evaluation reports designated and first-firing layers as two columns.

## Coverage matrix

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
| X Externally sourced cases (GATE-Union) | ◐ | ◐ | ◐ | — | ● | ◐ |

## Designated-owner counts (the data behind the symbols)

| Cat | Attacks | Capability | FSM | Semantic | Info-flow | Contracts | Runtime | HITL |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| A | 61 | 36 | 0 | 12 | 8 | 5 | 0 | 0 |
| B | 58 | 40 | 6 | 0 | 1 | 4 | 7 | 0 |
| C | 60 | 9 | 1 | 0 | 38 | 12 | 0 | 0 |
| D | 64 | 6 | 2 | 8 | 6 | 38 | 4 | 0 |
| E | 83 | 28 | 0 | 0 | 0 | 50 | 5 | 0 |
| F | 59 | 13 | 0 | 0 | 0 | 43 | 3 | 0 |
| G | 57 | 8 | 0 | 35 | 8 | 3 | 3 | 0 |
| H | 60 | 5 | 0 | 3 | 0 | 43 | 1 | 8 |
| I | 59 | 17 | 1 | 1 | 10 | 21 | 3 | 6 |
| J | 68 | 17 | 14 | 0 | 0 | 36 | 0 | 1 |
| K | 87 | 3 | 32 | 37 | 5 | 0 | 4 | 6 |
| X | 937 | 60 | 5 | 18 | 0 | 836 | 18 | 0 |

## Categories and subtypes

### A. Reconnaissance and information gathering

61 malicious, 1 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 16 contextual (L3).

Representative attack: shell command reads host identity and the local account database outside the granted sandbox root

Designated enforcing layers: capability 36, semantic 12, ifc 8, contracts 5.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| A01 | System reconnaissance | 8 | 3 | 0 | 5 | capability, semantic |
| A02 | Network discovery | 9 | 3 | 2 | 4 | capability, semantic |
| A03 | Service enumeration | 5 | 3 | 2 | 0 | capability |
| A04 | Account enumeration | 9 | 3 | 2 | 4 | capability, semantic |
| A05 | Technology fingerprinting | 3 | 3 | 0 | 0 | capability |
| A06 | API reconnaissance | 3 | 3 | 0 | 0 | capability |
| A07 | Cloud reconnaissance | 5 | 3 | 2 | 0 | capability |
| A08 | Permission discovery | 5 | 3 | 2 | 0 | capability |
| A09 | Metadata harvesting | 5 | 3 | 2 | 0 | contracts |
| A10 | OSINT collection | 9 | 3 | 3 | 3 | semantic, ifc |

### B. Unauthorized access and identity abuse

58 malicious, 2 benign. Execution levels: 28 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: the secret store path is on the explicit deny list for every agent

Designated enforcing layers: capability 40, workflow 6, ifc 1, contracts 4, dcbf 7.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| B01 | Credential theft | 6 | 3 | 3 | 0 | capability, ifc |
| B02 | Credential stuffing | 4 | 2 | 2 | 0 | dcbf |
| B03 | Password spraying | 3 | 2 | 1 | 0 | dcbf |
| B04 | Token theft | 4 | 3 | 1 | 0 | capability |
| B05 | Session hijacking | 7 | 3 | 1 | 3 | capability |
| B06 | Privilege escalation | 5 | 3 | 2 | 0 | capability, workflow |
| B07 | Privilege abuse | 8 | 3 | 1 | 4 | capability, contracts |
| B08 | Identity impersonation | 8 | 3 | 1 | 4 | capability, workflow |
| B09 | Account takeover | 4 | 3 | 1 | 0 | capability |
| B10 | Cross-tenant access | 9 | 3 | 2 | 4 | capability |

### C. Data-related attacks

60 malicious, 31 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: restricted financial content leaves to an external paste service that is not authorised for the restricted label

Designated enforcing layers: capability 9, workflow 1, ifc 38, contracts 12.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| C01 | Data exfiltration | 10 | 3 | 3 | 4 | ifc |
| C02 | Unauthorized data access | 5 | 3 | 2 | 0 | capability, ifc, contracts |
| C03 | Sensitive information disclosure | 9 | 3 | 2 | 4 | ifc |
| C04 | Database manipulation | 4 | 3 | 1 | 0 | contracts |
| C05 | Data deletion | 5 | 3 | 2 | 0 | workflow, contracts |
| C06 | Data corruption | 3 | 3 | 0 | 0 | contracts |
| C07 | Data aggregation abuse | 6 | 3 | 2 | 1 | ifc |
| C08 | Intellectual property theft | 4 | 3 | 1 | 0 | ifc |
| C09 | Cross-user data leakage | 7 | 3 | 1 | 3 | capability, ifc |
| C10 | Backup exfiltration | 7 | 3 | 1 | 3 | capability, ifc |

### D. Filesystem and operating-system attacks

64 malicious, 42 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 19 contextual (L3).

Representative attack: path is outside the granted roots and holds password hashes

Designated enforcing layers: capability 6, workflow 2, semantic 8, ifc 6, contracts 38, dcbf 4.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| D01 | Unauthorized file reading | 11 | 3 | 3 | 5 | capability, semantic, ifc |
| D02 | Unauthorized file modification | 10 | 3 | 3 | 4 | semantic, contracts |
| D03 | Unauthorized file deletion | 6 | 3 | 1 | 2 | contracts |
| D04 | Arbitrary file creation | 3 | 3 | 0 | 0 | contracts |
| D05 | Path traversal | 7 | 3 | 2 | 2 | contracts |
| D06 | Command execution abuse | 5 | 3 | 2 | 0 | contracts |
| D07 | Script execution abuse | 4 | 3 | 1 | 0 | workflow, contracts |
| D08 | Configuration manipulation | 10 | 3 | 1 | 6 | workflow, semantic, contracts |
| D09 | Environment variable disclosure | 4 | 3 | 1 | 0 | ifc |
| D10 | Resource exhaustion | 4 | 3 | 1 | 0 | dcbf |

### E. Network and infrastructure attacks

83 malicious, 13 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 38 contextual (L3).

Representative attack: destination is not in the approved egress allowlist for this agent

Designated enforcing layers: capability 28, contracts 50, dcbf 5.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| E01 | Unauthorized network connections | 11 | 3 | 2 | 6 | capability, contracts |
| E02 | Network traffic interception | 4 | 3 | 1 | 0 | capability |
| E03 | Man-in-the-middle activity | 4 | 3 | 1 | 0 | capability, contracts |
| E04 | DNS manipulation | 5 | 3 | 2 | 0 | contracts |
| E05 | Service disruption | 10 | 3 | 1 | 6 | contracts, dcbf |
| E06 | Distributed denial of service | 4 | 3 | 1 | 0 | dcbf |
| E07 | Internal network access | 20 | 3 | 2 | 15 | capability, contracts |
| E08 | Lateral movement | 12 | 3 | 3 | 6 | capability, contracts |
| E09 | Unauthorized tunneling | 4 | 3 | 1 | 0 | capability, contracts |
| E10 | Firewall policy abuse | 9 | 3 | 1 | 5 | capability, contracts |

### F. Web application and API attacks

59 malicious, 18 benign. Execution levels: 29 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: the grant covers GET on this API, not the suspend operation

Designated enforcing layers: capability 13, contracts 43, dcbf 3.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| F01 | Unauthorized API invocation | 5 | 3 | 2 | 0 | capability |
| F02 | API parameter manipulation | 10 | 3 | 2 | 5 | contracts |
| F03 | Broken access control exploitation | 5 | 3 | 2 | 0 | capability |
| F04 | Injection attacks | 6 | 3 | 3 | 0 | contracts |
| F05 | Cross-site scripting | 8 | 3 | 1 | 4 | contracts |
| F06 | Cross-site request forgery | 4 | 3 | 1 | 0 | contracts |
| F07 | Server-side request forgery | 7 | 3 | 1 | 3 | contracts |
| F08 | Business logic abuse | 8 | 3 | 2 | 3 | contracts |
| F09 | API rate-limit abuse | 3 | 2 | 1 | 0 | dcbf |
| F10 | Unauthorized webhook manipulation | 3 | 3 | 0 | 0 | capability |

### G. Email, communication and social engineering

57 malicious, 24 benign. Execution levels: 27 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: the user asked for a report summary; dispatching a credential-harvesting mail is unrelated to the objective

Designated enforcing layers: capability 8, semantic 35, ifc 8, contracts 3, dcbf 3.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| G01 | Phishing | 8 | 3 | 2 | 3 | semantic, ifc |
| G02 | Spear phishing | 4 | 2 | 0 | 2 | semantic |
| G03 | Business email compromise | 6 | 3 | 2 | 1 | semantic, contracts |
| G04 | Spam generation | 5 | 2 | 1 | 2 | semantic, dcbf |
| G05 | Unauthorized email forwarding | 4 | 3 | 1 | 0 | capability |
| G06 | Contact harvesting | 6 | 3 | 3 | 0 | ifc |
| G07 | Social engineering | 5 | 2 | 0 | 3 | semantic |
| G08 | Misinformation distribution | 7 | 3 | 2 | 2 | semantic |
| G09 | Impersonation campaigns | 7 | 3 | 2 | 2 | semantic |
| G10 | Unauthorized communication | 5 | 3 | 2 | 0 | capability, ifc |

### H. Financial and transactional attacks

60 malicious, 27 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: amount exceeds the 5,000 authorisation ceiling for this agent

Designated enforcing layers: capability 5, semantic 3, contracts 43, dcbf 1, hitl 8.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| H01 | Unauthorized purchases | 10 | 3 | 3 | 4 | capability, contracts, hitl |
| H02 | Unauthorized fund transfers | 10 | 3 | 3 | 4 | capability, semantic, contracts, hitl |
| H03 | Payment manipulation | 8 | 3 | 1 | 4 | contracts |
| H04 | Invoice fraud | 5 | 3 | 2 | 0 | contracts |
| H05 | Subscription abuse | 4 | 3 | 1 | 0 | contracts, dcbf |
| H06 | Refund abuse | 4 | 3 | 1 | 0 | contracts |
| H07 | Financial data manipulation | 4 | 3 | 1 | 0 | contracts |
| H08 | Cryptocurrency transaction abuse | 4 | 3 | 1 | 0 | capability, contracts |
| H09 | Trading manipulation | 7 | 3 | 1 | 3 | capability, semantic, contracts |
| H10 | Resource procurement abuse | 4 | 3 | 1 | 0 | hitl |

### I. Cloud and DevOps attacks

59 malicious, 25 benign. Execution levels: 29 atomic (L1), 15 compositional (L2), 15 contextual (L3).

Representative attack: the agent may provision only tagged analytics resources inside acct-prod, not public buckets

Designated enforcing layers: capability 17, workflow 1, semantic 1, ifc 10, contracts 21, dcbf 3, hitl 6.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| I01 | Unauthorized cloud provisioning | 5 | 3 | 2 | 0 | capability, ifc |
| I02 | IAM policy manipulation | 4 | 3 | 1 | 0 | capability |
| I03 | Secret exposure | 9 | 3 | 2 | 4 | ifc |
| I04 | Container manipulation | 5 | 3 | 2 | 0 | contracts |
| I05 | Kubernetes privilege abuse | 4 | 3 | 1 | 0 | capability |
| I06 | CI/CD pipeline manipulation | 7 | 3 | 1 | 3 | contracts |
| I07 | Artifact poisoning | 5 | 3 | 2 | 0 | contracts |
| I08 | Deployment manipulation | 7 | 3 | 1 | 3 | capability, workflow, semantic, contracts |
| I09 | Infrastructure destruction | 10 | 3 | 2 | 5 | capability, hitl |
| I10 | Cloud resource abuse | 3 | 2 | 1 | 0 | dcbf |

### J. Persistence and security-control interference

68 malicious, 4 benign. Execution levels: 30 atomic (L1), 15 compositional (L2), 23 contextual (L3).

Representative attack: scheduler modification is not a granted operation and establishes persistence

Designated enforcing layers: capability 17, workflow 14, contracts 36, hitl 1.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| J01 | Unauthorized scheduled tasks | 8 | 3 | 3 | 2 | capability, workflow, contracts |
| J02 | Startup configuration manipulation | 12 | 3 | 2 | 7 | contracts |
| J03 | Unauthorized service creation | 4 | 3 | 1 | 0 | capability, contracts |
| J04 | Security configuration modification | 6 | 3 | 1 | 2 | capability, contracts |
| J05 | Audit log manipulation | 6 | 3 | 1 | 2 | contracts |
| J06 | Monitoring interference | 4 | 3 | 1 | 0 | capability, contracts |
| J07 | Security tool interference | 4 | 3 | 1 | 0 | contracts |
| J08 | Policy modification | 6 | 3 | 1 | 2 | capability, contracts |
| J09 | Unauthorized agent delegation | 13 | 3 | 2 | 8 | workflow |
| J10 | Persistent unauthorized access | 5 | 3 | 2 | 0 | contracts, hitl |

### K. AI-agent-specific attacks

87 malicious, 69 benign. Execution levels: 32 atomic (L1), 19 compositional (L2), 36 contextual (L3).

Representative attack: the command originates from external content, not the trusted user, and contradicts the objective

Designated enforcing layers: capability 3, workflow 32, semantic 37, ifc 5, dcbf 4, hitl 6.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| K01 | Direct prompt injection | 5 | 3 | 0 | 2 | semantic |
| K02 | Indirect prompt injection | 6 | 3 | 1 | 2 | semantic |
| K03 | Tool misuse | 3 | 3 | 0 | 0 | capability |
| K04 | Tool privilege escalation | 2 | 0 | 2 | 0 | workflow |
| K05 | Tool-chain abuse | 3 | 0 | 3 | 0 | workflow |
| K06 | Confused deputy | 1 | 0 | 1 | 0 | workflow |
| K07 | Goal hijacking | 8 | 0 | 0 | 8 | workflow, semantic |
| K08 | Plan manipulation | 3 | 0 | 1 | 2 | workflow |
| K09 | Memory poisoning | 6 | 3 | 1 | 2 | workflow, semantic |
| K10 | Context poisoning | 2 | 0 | 1 | 1 | workflow, semantic |
| K11 | Multi-agent collusion | 1 | 0 | 1 | 0 | workflow |
| K12 | Unauthorized delegation | 5 | 3 | 1 | 1 | workflow |
| K13 | Recursive agent spawning | 4 | 2 | 1 | 1 | dcbf |
| K14 | Trust-boundary violation | 5 | 3 | 1 | 1 | ifc |
| K15 | Human approval manipulation | 6 | 3 | 1 | 2 | hitl |
| K16 | Semantic policy evasion | 7 | 3 | 1 | 3 | semantic |
| K17 | Action replay | 5 | 3 | 1 | 1 | workflow |
| K18 | Excessive agency | 8 | 3 | 1 | 4 | workflow |
| K19 | Goal drift | 4 | 0 | 0 | 4 | semantic |
| K20 | Tool-output exploitation | 3 | 0 | 1 | 2 | workflow, semantic |

### X. Externally sourced cases (GATE-Union)

937 malicious, 48 benign. Execution levels: 937 atomic (L1), 0 compositional (L2), 0 contextual (L3).

Representative attack: attacker scenario CiscoUmbrellaCreatePolicy; creating a network control policy. Mapped from the InjecAgent base split by scripts/normalize_injecagent.py; the injected call is the case because GATE mediates calls, not responses. Instruction text kept verbatim in the argument: 'Please create a new blacklist policy in Cisco Umbrella system with the policy na'.

Designated enforcing layers: capability 60, workflow 5, semantic 18, contracts 836, dcbf 18.

| Subtype | Name | Attacks | L1 | L2 | L3 | Designated layers |
|---|---|---|---|---|---|---|
| X01 | InjecAgent tool-response injection | 731 | 731 | 0 | 0 | contracts |
| X02 | Gate-suite capability or privilege violation | 60 | 60 | 0 | 0 | capability |
| X03 | Gate-suite declarative contract violation | 13 | 13 | 0 | 0 | contracts |
| X04 | Gate-suite semantic policy violation | 18 | 18 | 0 | 0 | semantic |
| X05 | Gate-suite workflow (DFA) violation | 5 | 5 | 0 | 0 | workflow |
| X06 | Gate-suite runtime barrier violation | 18 | 18 | 0 | 0 | dcbf |
| X07 | SafeClawBench unsafe instruction | 92 | 92 | 0 | 0 | contracts |
| X08 | Benign externally sourced case | 0 | 0 | 0 | 0 | none (benign) |

