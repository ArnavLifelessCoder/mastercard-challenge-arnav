"""
Coevolution loop: adversarial evolution of attack genomes against arm G.

For each vector, sample a population of genomes, score each against the fitted
arm G detector, keep the genomes that evade at the fixed operating point, mutate
them within the declared taxonomy ranges, repeat for N rounds. Report evasion
rate per vector per round and which parameter regions survive.

After evolution: retrain arm G on a benign population plus nothing else (it is
label-free, so the retrain is only recalibration), and report whether recall
recovers. Update each vector's difficulty with the observed evasion rate.

Run: python experiments/coevolution.py
"""

from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.ensemble import IsolationForest

from arts import generators as _gen_module  # noqa: F401  registration side effect
from arts.core import (
    REGISTRY,
    Actor,
    Context,
    PopulationConfig,
    Schema,
    Taxonomy,
    build_population,
    check_params,
    project,
    sample_params,
)
from arts.features import Featurizer

# Import the invariant and hybrid machinery from headline
from experiments.headline import (
    ALERT_RATE,
    Arm,
    grouped_split,
    invariant_score,
    pick_threshold,
)

SEED = 42
POP_PER_VECTOR = 50
N_ROUNDS = 8
MUTATION_RATE = 0.3
N_BENIGN_EPISODES = 20_000


def mutate_genome(
    genome: dict, spec: dict, rng: random.Random, rate: float = MUTATION_RATE
) -> dict:
    """Mutate a genome within the declared taxonomy ranges.

    Each parameter is perturbed independently with probability `rate`.
    The result is guaranteed to pass check_params.
    """
    out = dict(genome)
    for name, p in spec.items():
        if rng.random() > rate:
            continue
        t = p["type"]
        if t == "categorical":
            out[name] = rng.choice(p["values"])
        elif t == "bool":
            out[name] = not out[name]
        elif t == "int":
            lo, hi = p["range"]
            # perturb by up to 30% of the range
            delta = max(1, int((hi - lo) * 0.3))
            out[name] = max(int(lo), min(int(hi), int(out[name]) + rng.randint(-delta, delta)))
        elif t == "float":
            lo, hi = p["range"]
            delta = (hi - lo) * 0.3
            out[name] = max(float(lo), min(float(hi), out[name] + rng.uniform(-delta, delta)))
    return out


def main() -> int:
    schema, tax = Schema.load(), Taxonomy.load()
    rng = random.Random(SEED)
    np.random.seed(SEED)

    print("=== COEVOLUTION LOOP ===")
    print(f"Rounds: {N_ROUNDS}, Population per vector: {POP_PER_VECTOR}")

    # Step 1: Build a benign-only population and fit arm G
    print("\n--- Phase 1: Fitting arm G on benign traffic ---")
    benign_records = list(build_population(
        PopulationConfig(n_episodes=N_BENIGN_EPISODES, fraud_rate=0.0001, seed=SEED),
        schema=schema, taxonomy=tax))
    # filter to benign only
    benign_records = [r for r in benign_records if r["label"] == "benign"]
    print(f"Benign records: {len(benign_records)}")

    train, calib, _ = grouped_split(benign_records)
    arm_g = Arm("G hybrid v_attested", "v_attested", "hybrid", lambda r: r["label"] == "benign")
    arm_g.fit(train, calib, schema)
    print(f"Arm G fitted: threshold={arm_g.thr:.6f}")

    # Step 2: For each treatment vector, evolve genomes
    treatment_vectors = sorted(REGISTRY.attacks().keys())
    print(f"\nTreatment vectors: {len(treatment_vectors)}")

    results = {
        "config": {
            "seed": SEED,
            "pop_per_vector": POP_PER_VECTOR,
            "n_rounds": N_ROUNDS,
            "mutation_rate": MUTATION_RATE,
            "alert_rate": ALERT_RATE,
        },
        "per_vector": {},
    }

    # Make actors for generation
    actors = [
        Actor(
            account_id=f"acct_{i:07d}",
            device_fingerprint_id=f"dev_{rng.getrandbits(40):010x}",
            agent_id=f"agent_{rng.getrandbits(32):08x}",
            agent_provider_id=rng.choice(["prov_alpha", "prov_bravo", "prov_charlie"]),
            home_lat=round(rng.uniform(25.0, 48.0), 4),
            home_lon=round(rng.uniform(-123.0, -70.0), 4),
            typical_amount_minor=int(rng.lognormvariate(8.6, 0.7)),
            known_merchants=[f"mid_{rng.randint(1, 400):06d}" for _ in range(rng.randint(3, 12))],
            mandate_per_txn_cap_minor=rng.choice([25000, 50000, 100000, 250000]),
            mandate_allowlist=[f"MERCHANT {j:04d}" for j in range(4)],
        )
        for i in range(50)
    ]

    all_evasion_curves = {}

    for vid in treatment_vectors:
        gen_cls = REGISTRY.get(vid)
        gen = gen_cls(tax)
        spec = tax.params(vid)
        if not spec:
            print(f"  {vid}: no parameters, skipping coevolution")
            continue

        print(f"\n--- Evolving {vid} ---")
        evasion_per_round = []

        # Initial population
        population = []
        for _ in range(POP_PER_VECTOR):
            for attempt in range(32):
                g = sample_params(spec, rng)
                if gen.constraints(g):
                    population.append(g)
                    break

        for round_idx in range(N_ROUNDS):
            # Generate records from current population
            attack_records = []
            genome_to_records = defaultdict(list)
            for gi, genome in enumerate(population):
                ctx = Context(
                    now=datetime(2026, 3, 1, tzinfo=timezone.utc) + timedelta(hours=rng.randint(0, 2000)),
                    actor=rng.choice(actors),
                    schema=schema,
                    taxonomy=tax,
                    rng=rng,
                )
                try:
                    records = gen.emit(ctx, genome, f"coev_{vid}_{round_idx}_{gi}")
                    for r in records:
                        r.setdefault("label", "fraud")
                        r.setdefault("vector_id", vid)
                        r.setdefault("family", gen.family)
                        r.setdefault("genome", genome)
                        r.setdefault("campaign_id", f"coev_{vid}_{round_idx}_{gi}")
                        r["generator_version"] = "0.1.0"
                        r["taxonomy_version"] = tax.version
                    attack_records.extend(records)
                    genome_to_records[gi].extend(records)
                except Exception:
                    continue

            if not attack_records:
                evasion_per_round.append(0.0)
                continue

            # Score against arm G
            scores = arm_g.score(attack_records, schema)
            flagged = scores > arm_g.thr

            # Compute per-genome evasion: a genome evades if ALL its records evade
            evading_genomes = []
            for gi, genome in enumerate(population):
                recs = genome_to_records.get(gi, [])
                if not recs:
                    continue
                start_idx = sum(len(genome_to_records.get(j, [])) for j in range(gi))
                end_idx = start_idx + len(recs)
                if end_idx <= len(flagged):
                    genome_flagged = flagged[start_idx:end_idx]
                    if not genome_flagged.any():
                        evading_genomes.append(genome)

            evasion_rate = len(evading_genomes) / max(len(population), 1)
            evasion_per_round.append(round(evasion_rate, 4))
            print(f"  Round {round_idx}: evaders={len(evading_genomes)}/{len(population)} "
                  f"rate={evasion_rate:.3f}")

            # Select and mutate: keep evaders, fill rest with mutations
            if evading_genomes:
                new_pop = list(evading_genomes)
                while len(new_pop) < POP_PER_VECTOR:
                    parent = rng.choice(evading_genomes)
                    child = mutate_genome(parent, spec, rng)
                    # validate
                    problems = check_params(child, spec, vid)
                    if not problems and gen.constraints(child):
                        new_pop.append(child)
                    else:
                        new_pop.append(deepcopy(parent))
                population = new_pop[:POP_PER_VECTOR]
            else:
                # No evaders: resample from scratch
                new_pop = []
                for _ in range(POP_PER_VECTOR):
                    for attempt in range(32):
                        g = sample_params(spec, rng)
                        if gen.constraints(g):
                            new_pop.append(g)
                            break
                population = new_pop

        all_evasion_curves[vid] = evasion_per_round
        final_evasion = evasion_per_round[-1] if evasion_per_round else 0.0

        results["per_vector"][vid] = {
            "evasion_curve": evasion_per_round,
            "final_evasion_rate": final_evasion,
            "surviving_genome_sample": population[:3] if population else [],
        }

    # Step 3: Retrain arm G on benign + evolved attacks, check recovery
    print("\n--- Phase 3: Retrain and recovery check ---")
    # Arm G is label-free, so retrain is just recalibration on fresh benign
    fresh_benign = list(build_population(
        PopulationConfig(n_episodes=N_BENIGN_EPISODES, fraud_rate=0.0001, seed=SEED + 1),
        schema=schema, taxonomy=tax))
    fresh_benign = [r for r in fresh_benign if r["label"] == "benign"]
    train2, calib2, _ = grouped_split(fresh_benign, seed=SEED + 1)
    arm_g_retrained = Arm("G hybrid retrained", "v_attested", "hybrid",
                          lambda r: r["label"] == "benign")
    arm_g_retrained.fit(train2, calib2, schema)

    # Score evolved attacks against retrained arm G
    recovery_results = {}
    for vid, genomes_data in results["per_vector"].items():
        gen_cls = REGISTRY.get(vid)
        gen = gen_cls(tax)
        spec = tax.params(vid)
        surviving = genomes_data.get("surviving_genome_sample", [])
        if not surviving:
            continue

        evolved_records = []
        for gi, genome in enumerate(surviving):
            ctx = Context(
                now=datetime(2026, 6, 1, tzinfo=timezone.utc),
                actor=rng.choice(actors),
                schema=schema,
                taxonomy=tax,
                rng=rng,
            )
            try:
                records = gen.emit(ctx, genome, f"recovery_{vid}_{gi}")
                for r in records:
                    r.setdefault("label", "fraud")
                    r.setdefault("vector_id", vid)
                    r.setdefault("family", gen.family)
                    r.setdefault("genome", genome)
                    r.setdefault("campaign_id", f"recovery_{vid}_{gi}")
                    r["generator_version"] = "0.1.0"
                    r["taxonomy_version"] = tax.version
                evolved_records.extend(records)
            except Exception:
                continue

        if evolved_records:
            scores = arm_g_retrained.score(evolved_records, schema)
            recall = float((scores > arm_g_retrained.thr).mean())
            recovery_results[vid] = round(recall, 4)

    results["recovery"] = recovery_results

    # Step 4: Update difficulty with observed evasion rates
    difficulty_updates = {}
    for vid, data in results["per_vector"].items():
        observed = data["final_evasion_rate"]
        difficulty_updates[vid] = round(observed, 3)
    results["difficulty_updates"] = difficulty_updates

    # Summary
    print("\n" + "=" * 70)
    print(f"{'vector':10} {'initial':>8} {'final':>8} {'recovery':>10}")
    print("-" * 70)
    for vid in sorted(all_evasion_curves.keys()):
        curve = all_evasion_curves[vid]
        initial = curve[0] if curve else 0.0
        final = curve[-1] if curve else 0.0
        rec = recovery_results.get(vid, "n/a")
        rec_str = f"{rec:.3f}" if isinstance(rec, float) else rec
        print(f"{vid:10} {initial:>8.3f} {final:>8.3f} {rec_str:>10}")
    print("=" * 70)

    # Write results
    out = ROOT / "results" / "coevolution.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWritten: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
