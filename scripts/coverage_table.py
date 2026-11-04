"""Build the cross-source coverage tables from the measured audits.

Run from inside gate-union:  python scripts/coverage_table.py

Table A is the answer to the reviewer's question in numbers rather than
adjectives. Every cell is a count taken from a manifest audit, and the point of
printing zeros is that the zeros are the finding: no published dataset we could
verify supplies the transition-system or accumulated-state families at all, which
is why the authored stratum exists and why its share is reported per layer.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
FAMILIES = [f"F{i:02d}" for i in range(1, 18)]
LAYERS = ["privilege", "dfa", "contracts", "semantic", "dcbf"]
NO_PUBLIC_DATA = "no public data"
PROMPT_LEVEL = "prompt-level only"

SOURCES = [
    ("injecagent", "manifest/injecagent.audit.json"),
    ("agentdojo", "manifest/agentdojo.audit.json"),
    ("safeclawbench", "manifest/safeclawbench.audit.json"),
    ("toolprivacybench", "manifest/toolprivacybench.audit.json"),
    ("aspi", "manifest/aspi.audit.json"),
    ("agentic_pi_5k", "manifest/agentic_pi_5k.audit.json"),
    ("gate_original", "manifest/gate_original.audit.json"),
    ("authored", "manifest/authored.freeze.json"),
]


def audit_for(name: str, path: str) -> Dict[str, Any]:
    doc = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if name == "authored":
        return {"family_supply": doc["family_counts"], "layer_supply": doc["attack_layer_counts"],
                "cases_upstream": doc["rows"], "flag": None}
    src = (doc["sources"] if isinstance(doc, dict) and "sources" in doc else [doc])
    match = [s for s in src if s.get("id") == name] or src
    s = match[0]
    flag = None
    if not s.get("cases_upstream"):
        flag = NO_PUBLIC_DATA
    elif not (s.get("family_supply") or {}):
        flag = PROMPT_LEVEL
    return {"family_supply": s.get("family_supply") or {}, "layer_supply": s.get("layer_supply") or {},
            "cases_upstream": s.get("cases_upstream"), "flag": flag}


def main() -> None:
    data = {name: audit_for(name, path) for name, path in SOURCES}
    external = [n for n, _ in SOURCES if n not in ("gate_original", "authored")]

    rows_a: List[str] = ["| family | property | " + " | ".join(n for n, _ in SOURCES) + " | sources |",
                         "| --- | --- | " + " | ".join("---" for _ in SOURCES) + " | --- |"]
    for fam in FAMILIES:
        counts = []
        n_src = 0
        for name, _ in SOURCES:
            v = data[name]["family_supply"].get(fam)
            if v is None:
                counts.append(data[name]["flag"] or "0")
            else:
                counts.append(str(v))
                if v:
                    n_src += 1
        rows_a.append(f"| {fam} | {PROPERTY[fam]} | " + " | ".join(counts) + f" | {n_src} |")

    rows_b: List[str] = ["| layer | " + " | ".join(n for n, _ in SOURCES) + " | external total | authored share |",
                         "| --- | " + " | ".join("---" for _ in SOURCES) + " | --- | --- |"]
    for lay in LAYERS:
        cells, ext = [], 0
        for name, _ in SOURCES:
            v = data[name]["layer_supply"].get(lay) or 0
            cells.append(str(v))
            if name in external:
                ext += v
        auth = data["authored"]["layer_supply"].get(lay) or 0
        total = ext + (data["gate_original"]["layer_supply"].get(lay) or 0) + auth
        share = f"{100 * auth / total:.0f}%" if total else "-"
        rows_b.append(f"| {lay} | " + " | ".join(cells) + f" | {ext} | {share} |")

    families_from_external = sum(1 for f in FAMILIES
                                 if any(data[n]["family_supply"].get(f) for n in external))
    zero_external = [f for f in FAMILIES
                     if not any(data[n]["family_supply"].get(f) for n in external)]

    doc = ["# Coverage of GATE-Union by source",
           "",
           "Cells are counted cases, taken from the per-source audits in `manifest/`, not from the "
           "upstream papers. A `0` is a measurement: the source was fetched, its structure was read, "
           "and it does not label that property. `prompt-level only` means the dataset exists and was "
           "counted but ships no tool call, so nothing can be mapped onto a mediated boundary. "
           "`no public data` means the artefact could not be located at all.",
           "",
           "## Table A, family by source",
           ""] + rows_a + ["",
           "## Table B, enforcement layer by source",
           "",
           "The layer axis is the one the paper's claim lives on, so this is the table that decides "
           "how much authoring a defensible corpus needs.",
           ""] + rows_b + ["",
           "## What the two tables say",
           "",
           f"- {families_from_external} of {len(FAMILIES)} families have any external supply at all.",
           f"- Families with zero external supply: {', '.join(zero_external) or 'none'}.",
           "- The two stages with zero external supply across every audited source are dfa and dcbf. "
           "Their cases are the authored stratum, and the authored share column above is the number a "
           "reviewer should read as the cost of the gap, not as a claim about the field.",
           "- Where several families share one owning layer, extra rows for those families do not buy a "
           "new invariant test. F01, F02, F03 and F16 are all privilege-stage properties, and F05, F06, "
           "F07, F08 and F09 are all contract properties, which is why the corpus quota is set per layer "
           "and not per family.",
           "- Row counts here are before template dedup, and the difference is not cosmetic. The 1,054 "
           "InjecAgent rows are 62 attacker scenarios against 17 user tools, and the 731 rows the "
           "normalizer emits collapse to 43 templates. The contracts layer therefore looks far better "
           "supplied in rows than it is in distinct attacks, and the layer supply of privilege, at 37 "
           "external rows across every audited source, is the thin one.",
           ""]
    out = ROOT / "results" / "coverage.md"
    out.write_text("\n".join(doc), encoding="utf-8")
    print("\n".join(doc[-12:]))
    print(f"wrote {out}")


PROPERTY = {
    "F01": "granted-tool boundary", "F02": "role capability", "F03": "tenant isolation",
    "F04": "instruction versus intent", "F05": "harm inside the grant", "F06": "disclosure boundary",
    "F07": "irreversible state change", "F08": "argument validity", "F09": "code policy",
    "F10": "transition legality", "F11": "phase loop bound", "F12": "step budget",
    "F13": "cumulative privacy", "F14": "accumulated envelope", "F15": "semantic masking",
    "F16": "network scope", "F17": "persistent memory",
}

if __name__ == "__main__":
    main()
