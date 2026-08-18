"""Smoke test. Run before trusting anything downstream.

Checks, in order of how badly each one would waste a day:
  1. every emitted record validates against the auth record schema
  2. every emitted genome sits inside its declared taxonomy ranges
  3. the three views actually differ, and v_network really cannot see intent
  4. campaign grouping holds, so a split on campaign_id cannot leak
  5. class balance is roughly what was asked for
  6. the hard part: on v_network, treatment records are not trivially separable
     from BEN-01 by amount alone
"""

from __future__ import annotations

import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arts import generators  # noqa: F401  (registration side effect)
from arts.core import (
    REGISTRY,
    PopulationConfig,
    Schema,
    Taxonomy,
    build_population,
    check_params,
    project,
    validate_record,
)

FAILURES: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILURES.append(msg)


def main() -> int:
    schema = Schema.load()
    tax = Taxonomy.load()

    cov = REGISTRY.coverage(tax)
    print(f"taxonomy v{tax.version}  vectors={len(tax.vectors)}  implemented={len(tax.implemented())}")
    print(f"generators built: {len(cov['built'])} -> {cov['built']}")
    print(f"declared but not built: {len(cov['declared_not_built'])}")
    check(not cov["built_not_declared"], f"generators with no taxonomy entry: {cov['built_not_declared']}")

    cfg = PopulationConfig(n_episodes=4000, fraud_rate=0.02, seed=11)
    records = list(build_population(cfg, schema=schema, taxonomy=tax))
    print(f"records: {len(records)} from {cfg.n_episodes} episodes")

    # 1. schema validity
    bad = 0
    for r in records:
        problems = validate_record(r, schema)
        if problems:
            bad += 1
            if bad <= 3:
                print(f"  INVALID {r.get('vector_id')}: {problems[:4]}")
    check(bad == 0, f"{bad} records failed schema validation")

    # 2. genome inside declared ranges
    genome_problems: list[str] = []
    for r in records:
        vid = r.get("vector_id")
        if vid and r.get("genome"):
            genome_problems += check_params(r["genome"], tax.params(vid), vid)
    check(not genome_problems, f"genome drift: {genome_problems[:5]}")

    # 3. views
    nf = set(schema.view_fields("v_network"))
    af = set(schema.view_fields("v_attested"))
    of = set(schema.view_fields("v_omniscient"))
    print(f"view sizes: v_network={len(nf)} v_attested={len(af)} v_omniscient={len(of)}")
    check(nf < af < of, "views are not strictly nested and growing")
    for leaked in ("intent_text_embedding", "cart_text_embedding", "consent_recorded_hash",
                   "memory_write_to_use_latency_hours", "user_confirmation_events"):
        check(leaked not in nf, f"{leaked} leaked into v_network")
        check(leaked in af, f"{leaked} missing from v_attested")
    check("label" not in of and "genome" not in of, "ground truth leaked into a view")

    sample = records[0]
    check(len(project(sample, "v_network", schema)) < len(project(sample, "v_omniscient", schema)),
          "projection did not reduce field count")

    # 4. campaign integrity
    by_campaign: dict[str, set[str]] = {}
    for r in records:
        by_campaign.setdefault(r["campaign_id"], set()).add(str(r.get("vector_id")))
    check(all(len(v) == 1 for v in by_campaign.values()), "a campaign spans more than one vector")
    multi = sum(1 for c, _ in by_campaign.items() if sum(1 for r in records if r["campaign_id"] == c) > 1)
    print(f"campaigns: {len(by_campaign)}, multi-record: {multi}")

    # 5. balance
    labels = Counter(r["label"] for r in records)
    frac = labels["fraud"] / len(records)
    print(f"label mix: {dict(labels)}  fraud share={frac:.3%}")
    check(0.005 < frac < 0.25, f"fraud share {frac:.3%} is implausible")
    print("by vector:", dict(Counter(r.get("vector_id") or "BENIGN" for r in records).most_common()))

    # 6. the honesty check
    treatment = {
        "AGH-01", "AGH-02", "AGH-03", "AGH-04", "AGH-07", "AGH-09",
        "MND-01", "MND-02", "MND-03", "MND-04", "MND-05", "MND-07",
        "IDS-01", "IDS-02", "IDS-03", "IDS-04", "IDS-05", "IDS-07",
        "XRL-01", "XRL-03", "XRL-04", "XRL-06",
    }
    ben = [r["amount_minor"] for r in records if r["vector_id"] == "BEN-01"]
    trt = [r["amount_minor"] for r in records if r.get("vector_id") in treatment]
    if ben and trt:
        bm, tm = statistics.median(ben), statistics.median(trt)
        print(f"median amount: BEN-01={bm/100:.2f} treatment={tm/100:.2f} ratio={tm/bm:.2f}")
        check(tm / bm < 8.0, "treatment amounts dwarf benign, v_network baseline will win for free")
    trt_approved = [r["approved"] for r in records if r.get("vector_id") in treatment]
    if trt_approved:
        rate = sum(trt_approved) / len(trt_approved)
        print(f"treatment approval rate: {rate:.1%}")
        check(rate > 0.9, "treatment attacks are being declined, they should authorize cleanly")

    print()
    if FAILURES:
        print(f"FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print("  -", f)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
