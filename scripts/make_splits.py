"""Leakage-safe splits for GATE-Union, by template family and not by row.

Run from inside gate-union:  python scripts/make_splits.py

Two rules, both from SPEC 12. A split is made by `template_family`, so two
paraphrases of one attack can never sit on opposite sides and threshold selection
cannot see the test cases through a synonym. And the authored stratum is separated
by provenance as well as by split, because D5 requires external-only and
full-corpus numbers.

The stratification is by owning layer: a random family draw can leave a split with
no dcbf cases at all, which would make threshold calibration on that split blind
to the stage the paper is most often asked about.
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [ROOT / "authored" / "authored.jsonl",
           ROOT / "authored" / "balancing.jsonl",
           ROOT / "gate_original" / "gate_original.jsonl",
           ROOT / "harmonized" / "injecagent.jsonl"]
OUT = ROOT / "splits"
SEED = 20261103
RATIOS = {"calibration": 0.2, "dev": 0.2, "test": 0.6}


def main() -> None:
    rows: List[Dict[str, Any]] = []
    for path in SOURCES:
        if path.exists():
            rows.extend(json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip())

    families: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        key = (r["template_family"], r["source_dataset"])
        families[key].append(r)

    rng = random.Random(SEED)
    by_layer: Dict[str, List[Any]] = defaultdict(list)
    for key, members in families.items():
        layer = members[0]["primary_layer"] or "control"
        by_layer[layer].append(key)

    assignment: Dict[Any, str] = {}
    for layer, keys in by_layer.items():
        rng.shuffle(keys)
        n = len(keys)
        c = int(round(n * RATIOS["calibration"]))
        d = int(round(n * RATIOS["dev"]))
        for i, key in enumerate(keys):
            assignment[key] = "calibration" if i < c else ("dev" if i < c + d else "test")

    OUT.mkdir(exist_ok=True)
    counts: Dict[str, int] = defaultdict(int)
    writers = {name: (OUT / f"{name}.jsonl").open("w", encoding="utf-8", newline="\n")
               for name in RATIOS}
    leakage = 0
    for r in rows:
        key = (r["template_family"], r["source_dataset"])
        split = assignment[key]
        counts[split] += 1
        record = dict(r)
        record["split"] = split
        writers[split].write(json.dumps(record, ensure_ascii=False) + "\n")
    for w in writers.values():
        w.close()

    # A template must appear in exactly one split; assert it rather than trust it.
    seen: Dict[Any, set] = defaultdict(set)
    for name in RATIOS:
        for line in (OUT / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            seen[rec["template_family"]].add(name)
    leakage = sum(1 for v in seen.values() if len(v) > 1)

    manifest = {"seed": SEED, "ratios": RATIOS, "rows": len(rows),
                "counts": dict(counts), "templates": len(seen),
                "templates_spanning_splits": leakage,
                "grouping_key": "template_family + source_dataset",
                "stratified_by": "primary_layer"}
    (OUT / "splits.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    for name in RATIOS:
        sub = [json.loads(l) for l in (OUT / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()]
        layers = defaultdict(int)
        for r in sub:
            layers[r["primary_layer"] or "control"] += 1
        print(name, len(sub), dict(sorted(layers.items())))
    assert leakage == 0, "a template family spans two splits"


if __name__ == "__main__":
    main()
