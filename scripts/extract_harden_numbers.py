"""Extract every manuscript number from the canonical hardened-contract run.

Reads adminfix.* (A5_full for the full pipeline; A3_det_pipeline and
A4_plus_dcbf for the changed ablation rows). Prints measured values only;
nothing here is hand-entered into the paper.
"""
import json
import statistics
from collections import Counter

RESULTS = "results"


def load(name):
    return [json.loads(l) for l in open(f"{RESULTS}/{name}.jsonl", encoding="utf-8")]


def is_attack(r):
    return r["expected_outcome"] != "allow"


def pct_block(rows):
    """first-rejecting stage over attacks (BLOCK only)."""
    return Counter(
        r["blocking_stage"] for r in rows if is_attack(r) and r["outcome"] == "BLOCK"
    )


def main():
    rows = load("adminfix.A5_full")
    atk = [r for r in rows if is_attack(r)]
    ben = [r for r in rows if not is_attack(r)]
    print(f"rows={len(rows)} attacks={len(atk)} benign={len(ben)}")

    # --- first rejecting stage over attacks ---
    frs = pct_block(rows)
    esc_atk = sum(1 for r in atk if r["outcome"] == "ESCALATE")
    print("\n== first_rejecting_stage (attacks) ==")
    for k, v in sorted(frs.items(), key=lambda x: -x[1]):
        print(f"  {k} = {v}")
    print(f"  escalate = {esc_atk}")
    print(f"  sum = {sum(frs.values()) + esc_atk}")

    # --- declared vs firing agreement ---
    agree = sum(1 for r in atk if r["primary_layer"] == r["blocking_stage"])
    differ = len(atk) - agree
    print("\n== declared-vs-firing ==")
    print(f"  agree = {agree}  differ = {differ}  total = {len(atk)}")
    # per declared layer, where do the contract-declared ones fire
    for layer in ("contracts", "dcbf", "privilege", "dfa", "semantic"):
        declared = [r for r in atk if r["primary_layer"] == layer]
        fired_here = sum(1 for r in declared if r["blocking_stage"] == layer)
        others = Counter(
            (r["outcome"], r["blocking_stage"])
            for r in declared
            if r["blocking_stage"] != layer
        )
        print(f"  {layer}: agrees {fired_here}/{len(declared)}  elsewhere={dict(others)}")

    # --- latency ---
    all_lat = [r["latency_ms"] for r in rows]
    short = [r["latency_ms"] for r in rows if r["sss"] is None]
    embed = [r["latency_ms"] for r in rows if r["sss"] is not None]

    def stats(v):
        v = sorted(v)
        def p(q):
            i = min(len(v) - 1, int(round(q * (len(v) - 1))))
            return v[i]
        return dict(
            n=len(v), mean=round(statistics.mean(v), 3), med=round(statistics.median(v), 3),
            p95=round(p(0.95), 3), p99=round(p(0.99), 3), max=round(max(v), 3),
        )

    print("\n== latency ==")
    print("  ALL          ", stats(all_lat))
    print("  short-circuit", stats(short))
    print("  embedding    ", stats(embed))

    # --- escalation SSS bands ---
    ea = sorted(r["sss"] for r in atk if r["outcome"] == "ESCALATE")
    eb = sorted(r["sss"] for r in ben if r["outcome"] == "ESCALATE")

    def band(v):
        return dict(n=len(v), min=round(min(v), 4), med=round(statistics.median(v), 4), max=round(max(v), 4))

    print("\n== escalation SSS ==")
    print("  attacks  ", band(ea))
    print("  benign   ", band(eb))
    print("  combined ", band(ea + eb))

    # --- threshold sweep (exact over stored scores) ---
    # deterministic attack blocks never reach semantic: constant count
    det_atk_block = sum(1 for r in atk if r["sss"] is None and r["outcome"] == "BLOCK")
    sem_atk = [r["sss"] for r in atk if r["sss"] is not None]  # reached semantic
    det_ben_block = sum(1 for r in ben if r["sss"] is None and r["outcome"] == "BLOCK")
    sem_ben = [r["sss"] for r in ben if r["sss"] is not None]
    print(f"\n== sweep inputs: det_atk_block={det_atk_block} sem_atk={len(sem_atk)} "
          f"det_ben_block={det_ben_block} sem_ben={len(sem_ben)} ==")
    safe = 0.70
    print("  thr | atk_blk atk_esc escapes | ben_allow ben_esc ben_blk")
    for t in (0.35, 0.40, 0.45, 0.50, 0.55, 0.60):
        ab = det_atk_block + sum(1 for s in sem_atk if s < t)
        ae = sum(1 for s in sem_atk if t <= s <= safe)
        escapes = sum(1 for s in sem_atk if s > safe)
        ba = sum(1 for s in sem_ben if s > safe)
        be = sum(1 for s in sem_ben if t <= s <= safe)
        bb = det_ben_block + sum(1 for s in sem_ben if s < t)
        print(f"  {t:.2f}| {ab:6d} {ae:6d} {escapes:6d} | {ba:8d} {be:6d} {bb:8d}")

    # --- ablation rows A3/A4 ---
    for key in ("adminfix.A3_det_pipeline", "adminfix.A4_plus_dcbf"):
        ar = load(key)
        a_atk = [r for r in ar if is_attack(r)]
        a_ben = [r for r in ar if not is_attack(r)]
        blk = sum(1 for r in a_atk if r["outcome"] == "BLOCK")
        esc = sum(1 for r in a_atk if r["outcome"] == "ESCALATE")
        escapes = sum(1 for r in a_atk if r["outcome"] == "ALLOW")
        ballow = sum(1 for r in a_ben if r["outcome"] == "ALLOW")
        print(f"\n== {key} == blocked={blk} esc={esc} escapes={escapes} benign_allow={ballow}/{len(a_ben)}")


if __name__ == "__main__":
    main()
