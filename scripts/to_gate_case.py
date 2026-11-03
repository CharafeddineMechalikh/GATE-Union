"""Turn a GATE-Union row back into the dict that benchmarks/harness.py consumes.

The round trip exists to prove the harmonisation is lossless: every field the
reference monitor needs must survive conversion to the common schema and back.
Run from gate-union/:  python scripts/to_gate_case.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / "gate_original" / "gate_original.jsonl"
SUITE = ROOT.parent / "benchmarks" / "attack_suite.json"


def to_gate_case(row: dict) -> dict:
    ctx = row["execution_context"]
    case = {
        "id": row["source_case_id"],
        "category": row["source_category"],
        "profile": ctx["profile"],
        "tool": row["tool_name"],
        "args": row["tool_arguments"],
        "should_pass": row["source_expected_pass"],
        "expected_stage": row["source_expected_stage"],
        "description": row["attacker_objective"],
    }
    if ctx.get("state") is not None:
        case["state"] = ctx["state"]
    if ctx.get("dcbf_envelope") is not None:
        case["envelope"] = ctx["dcbf_envelope"]
    if row.get("user_intent") is not None:
        case["intent"] = row["user_intent"]
    return case


def without_nulls(case: dict) -> dict:
    """Drop keys whose value is None, since the source writes some explicitly.

    The harness reads these fields with .get(), so a present null and an absent
    key mean the same thing to the monitor; comparing them as different would be
    an artefact of this test rather than a property of the data.
    """
    return {k: v for k, v in case.items() if v is not None}


def main() -> None:
    rows = [json.loads(line) for line in ROWS.read_text(encoding="utf-8").splitlines()]
    original = {c["id"]: c for c in json.loads(SUITE.read_text(encoding="utf-8"))["cases"]}

    mismatches = []
    for row in rows:
        back = without_nulls(to_gate_case(row))
        source = without_nulls(original[row["source_case_id"]])
        if back != source:
            diff = {
                k: (source.get(k), back.get(k))
                for k in set(source) | set(back)
                if source.get(k) != back.get(k)
            }
            mismatches.append((row["case_id"], diff))

    print(f"rows {len(rows)}, round trip mismatches {len(mismatches)}")
    for cid, diff in mismatches[:10]:
        print(cid, json.dumps(diff)[:220])


if __name__ == "__main__":
    main()
