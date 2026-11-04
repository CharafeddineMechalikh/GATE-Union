"""Run GATE-Union rows through the real five-stage monitor.

Run from inside gate-union:
    python scripts/run_union.py --strata authored gate_original injecagent
    python scripts/run_union.py --dedup            # one representative per template
    python scripts/run_union.py --ablations A4_full A2_det_pipeline

This does not re-implement measurement. It imports benchmarks/harness.py, which
is the single path every published number comes from, and adapts a union row to
the shape that path expects. The profile and the barrier envelope travel inside
each row, so a run is reproducible from the dataset alone and does not depend on
the suite file the original numbers were produced with.

Reported per row: the monitor's own answer (outcome, first rejecting stage, the
stage that owns the property in the label, latency) and nothing else, so the
analysis is a join against the frozen labels rather than a re-derivation.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT.parent / "benchmarks"
sys.path.insert(0, str(BENCH))
sys.path.insert(1, str(ROOT.parent))  # the gate package lives at the project root

import harness  # noqa: E402  (path injected above)

FILES = {
    "authored": ROOT / "authored" / "authored.jsonl",
    "gate_original": ROOT / "gate_original" / "gate_original.jsonl",
    "injecagent": ROOT / "harmonized" / "injecagent.jsonl",
}
RESULTS = ROOT / "results"


def load_rows(strata: List[str], dedup: bool) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name in strata:
        path = FILES[name]
        if not path.exists():
            print(f"missing stratum file {path}, skipped")
            continue
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    if dedup:
        kept: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            kept.setdefault(r["template_family"], r)
        rows = list(kept.values())
    return rows


def to_harness_case(row: Dict[str, Any]) -> Dict[str, Any]:
    ctx = row["execution_context"]
    intent = row.get("user_intent") or row.get("attacker_objective") or ""
    return {
        "id": row["case_id"],
        "category": row["attack_family"],
        "tool": row["tool_name"],
        "args": row["tool_arguments"],
        "intent": intent,
        "state": ctx.get("state") or {},
        "envelope": ctx.get("dcbf_envelope"),
        "should_pass": row["expected_outcome"] == "allow",
        "expected_stage": row["primary_layer"] or None,
    }


async def run(rows: List[Dict[str, Any]], stages: set, suite: Dict[str, Any]) -> List[Dict[str, Any]]:
    corpus = harness.read_corpus()
    centroids = suite.get("benign_centroids") or {}
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(rows, 1):
        case = to_harness_case(row)
        profile = harness.build_profile(f"{case['id']}.agent", row["execution_context"]["profile_spec"])
        monitor = harness.build_monitor(
            profile, stages, seed=True, benign_centroids=centroids, corpus=corpus,
            envelope=case["envelope"])
        result = await harness.run_case(monitor, case, profile)
        result.update({
            "source_dataset": row["source_dataset"],
            "attack_family": row["attack_family"],
            "attack_vector": row["attack_vector"],
            "expected_outcome": row["expected_outcome"],
            "primary_layer": row["primary_layer"],
            "template_family": row["template_family"],
        })
        out.append(result)
        if i % 100 == 0:
            print(f"  {i}/{len(rows)}", flush=True)
    return out


def summarise(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    def ternary(r: Dict[str, Any]) -> str:
        return "escalate" if r["escalated"] else ("allow" if r["is_allowed"] else "block")

    def wilson(k: int, n: int, z: float = 1.96) -> str:
        if n == 0:
            return "-"
        p = k / n
        d = 1 + z * z / n
        c = (p + z * z / (2 * n)) / d
        h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
        return f"[{100 * (c - h):.1f},{100 * (c + h):.1f}]"

    attacks = [r for r in results if r["expected_outcome"] != "allow"]
    allowed = [r for r in results if r["expected_outcome"] == "allow"]
    contained = sum(1 for r in attacks if ternary(r) != "allow")
    exact = sum(1 for r in results if ternary(r) == r["expected_outcome"])
    fb = sum(1 for r in allowed if ternary(r) == "block")
    esc = sum(1 for r in allowed if ternary(r) == "escalate")
    per_layer: Dict[str, Dict[str, int]] = defaultdict(lambda: {"n": 0, "contained": 0, "attributed": 0})
    for r in attacks:
        lay = r["primary_layer"] or "none"
        per_layer[lay]["n"] += 1
        if ternary(r) != "allow":
            per_layer[lay]["contained"] += 1
        if r["blocking_stage"] == (r["primary_layer"] or None):
            per_layer[lay]["attributed"] += 1
    per_family = defaultdict(lambda: {"n": 0, "contained": 0})
    for r in attacks:
        per_family[r["attack_family"]]["n"] += 1
        per_family[r["attack_family"]]["contained"] += ternary(r) != "allow"
    first_stage = Counter(r["blocking_stage"] or "none" for r in attacks)
    lat = sorted(r["latency_ms"] for r in results)
    return {
        "rows": len(results),
        "attacks": len(attacks),
        "controls": len(allowed),
        "containment": {"rate": round(contained / len(attacks), 4) if attacks else None,
                        "wilson95": wilson(contained, len(attacks)) if attacks else "-"},
        "exact_ternary": {"rate": round(exact / len(results), 4),
                          "wilson95": wilson(exact, len(results))},
        "false_block_on_controls": fb,
        "escalate_on_controls": esc,
        "per_layer": {k: {"n": v["n"],
                          "containment": round(v["contained"] / v["n"], 4) if v["n"] else None,
                          "owning_stage_agreement": round(v["attributed"] / v["n"], 4) if v["n"] else None}
                      for k, v in sorted(per_layer.items())},
        "per_family": {k: {"n": v["n"], "containment": round(v["contained"] / v["n"], 4)}
                       for k, v in sorted(per_family.items())},
        "first_rejecting_stage": dict(first_stage),
        "latency_ms": {"median": lat[len(lat) // 2] if lat else None,
                       "p99": lat[int(len(lat) * 0.99)] if lat else None,
                       "max": lat[-1] if lat else None},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strata", nargs="+", default=["authored", "gate_original", "injecagent"])
    ap.add_argument("--ablations", nargs="+", default=["A4_full"],
                    help="keys of harness.ABLATIONS")
    ap.add_argument("--dedup", action="store_true", help="one representative per template family")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="union")
    args = ap.parse_args()

    rows = load_rows(args.strata, args.dedup)
    if args.limit:
        rows = rows[:args.limit]
    suite = harness.load_suite()
    print(f"union rows {len(rows)} from {args.strata} (dedup={args.dedup})")

    RESULTS.mkdir(exist_ok=True)
    for key in args.ablations:
        stages = harness.ABLATIONS[key]
        print(f"running {key} over {sorted(stages)}", flush=True)
        results = asyncio.run(run(rows, stages, suite))
        detail = RESULTS / f"{args.out}.{key}.jsonl"
        with detail.open("w", encoding="utf-8", newline="\n") as fh:
            for r in results:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        summary = summarise(results)
        (RESULTS / f"{args.out}.{key}.summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
