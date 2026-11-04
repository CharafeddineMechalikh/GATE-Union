"""Load GATE-Union rows by split and provenance stratum.

Run from inside gate-union:
    python scripts/load.py --split test --stratum external
    python scripts/load.py --split calibration --layer dcbf --dedup

`external` means cases from other groups' published datasets, which is the only
stratum whose labels we did not write. It exists because D5 commits to reporting
external-only and full-corpus numbers separately; a caller who forgets the flag
silently blends the authored cases back in.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List

ROOT = Path(__file__).resolve().parent.parent
STRATA = {
    "external": [ROOT / "harmonized" / "injecagent.jsonl"],
    "gate_original": [ROOT / "gate_original" / "gate_original.jsonl"],
    "authored": [ROOT / "authored" / "authored.jsonl",
                 ROOT / "authored" / "balancing.jsonl"],
}


def rows(strata: List[str], split: str | None, dedup: bool) -> Iterator[Dict[str, Any]]:
    seen: set = set()
    for name in strata:
        for path in STRATA[name]:
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if split and row.get("split", split) != split:
                    # the split label lives on the split files, not the stratum files
                    if not (ROOT / "splits" / f"{split}.jsonl").exists():
                        raise SystemExit("run scripts/make_splits.py before loading by split")
                    continue
                if dedup:
                    key = (row["template_family"], row["source_dataset"])
                    if key in seen:
                        continue
                    seen.add(key)
                yield row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default=None, choices=[None, "calibration", "dev", "test"])
    ap.add_argument("--stratum", default="all", choices=["all", "external", "gate_original", "authored"])
    ap.add_argument("--layer", default=None)
    ap.add_argument("--dedup", action="store_true")
    args = ap.parse_args()

    strata = list(STRATA) if args.stratum == "all" else [args.stratum]
    datasets = {"external": {"injecagent"}, "gate_original": {"gate_original"},
                "authored": {"authored"}}
    allowed = (set().union(*(datasets[s] for s in strata)))
    if args.split:
        path = ROOT / "splits" / f"{args.split}.jsonl"
        if not path.exists():
            raise SystemExit("run scripts/make_splits.py first")
        source = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        selected = [r for r in source if r["source_dataset"] in allowed]
    else:
        selected = [r for r in rows(strata, None, False) if r["source_dataset"] in allowed]

    if args.layer:
        selected = [r for r in selected if r["primary_layer"] == args.layer]
    if args.dedup and args.split:
        kept: Dict[tuple, Dict[str, Any]] = {}
        for r in selected:
            kept.setdefault((r["template_family"], r["source_dataset"]), r)
        selected = list(kept.values())

    print(json.dumps({"rows": len(selected), "split": args.split, "stratum": args.stratum,
                      "layer": args.layer, "dedup": args.dedup,
                      "by_family": {k: v for k, v in sorted(
                          {r["attack_family"]: sum(1 for x in selected if x["attack_family"] == r["attack_family"])
                           for r in selected}.items())}}, indent=2))
    out = ROOT / "results" / f"load.{args.split or 'all'}.{args.stratum}.jsonl"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for r in selected:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
