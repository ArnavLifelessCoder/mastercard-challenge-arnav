# ARTS: Agentic Red Team Simulator

Closed-loop red team / blue team system for agentic payment fraud.
Mastercard Innovation Challenge @ GFF 2026.

## Layout

```
schema/taxonomy.yaml        Identify. 42 vectors, 5 families, the attack genome,
                            with measured difficulty from the coevolution loop.
schema/auth_record.yaml     Wire format. ISO 8583 core plus agentic extensions,
                            every field tagged with the vantage that holds it.
arts/core.py                Record model, validation, vantage projection, generator contract.
arts/generators.py          29 attack generators, 3 benign.
arts/features.py            One featurizer, applied per view.
experiments/headline.py     Seven-arm detection experiment.
experiments/coevolution.py  Adversarial genome evolution against the defense.
web/                        FastAPI service plus single-page prototype.
tests/smoke.py              Correctness gate. Run before trusting any result.
results/                    headline.json, coevolution.json.
GUIDE.md                    Engineering guide, conventions, and remaining work.
```

## Run

```bash
pip install -r requirements.txt
python tests/smoke.py                  # must print PASS
python experiments/headline.py         # writes results/headline.json
python experiments/coevolution.py      # writes results/coevolution.json
python -m uvicorn web.app:app --reload # prototype on http://127.0.0.1:8000
```

## The idea in one paragraph

Agentic payment fraud produces authorizations that are cryptographically valid,
mandate-compliant, fast, and approved. The evidence that would expose the attack
(what the user actually asked for, whether they confirmed, where a payee change
came from) sits inside the agent platform and never crosses the payment network.
So every field in the record carries a `vantage`, and the dataset is projected
into three views before any model sees it:

- `v_network` (69 fields) is what the rails carry today. The incumbent trains here.
- `v_attested` (111 fields) adds issuer history plus every field an attestation
  or mandate extension could plausibly carry. The intent-provenance view.
- `v_omniscient` (112 fields) is the ceiling, not a deployable target.

The projection is the experiment.

## Detection result

`python experiments/headline.py`: 60,000 episodes, 29 attack generators,
grouped split on `campaign_id`, threshold pinned at a 0.5% alert rate on
legitimate traffic and calibrated on a held-out benign slice. Treatment is 22
agentic vectors that never appear in training, control is 7 classical
GenAI-assisted vectors that do.

| arm | view | control AUC | treatment AUC | treatment recall | alert rate |
|---|---|---|---|---|---|
| A supervised | v_network | 0.999 | 0.766 | 0.344 | 0.008 |
| B supervised | v_attested | 0.999 | 0.853 | 0.355 | 0.007 |
| C novelty | v_network | 0.744 | 0.874 | 0.309 | 0.006 |
| D novelty | v_attested | 0.696 | 0.981 | 0.497 | 0.007 |
| E supervised oracle | v_attested | 0.999 | 1.000 | 0.972 | 0.007 |
| F invariants only | v_attested | 0.500 | 0.730 | 0.461 | 0.001 |
| G hybrid (D or F) | v_attested | 0.696 | 0.984 | 0.628 | 0.007 |

Arm A is the incumbent, and it is excellent at what it was built for: 0.999 AUC
on classical fraud. On agentic fraud it never trained on, ranking quality falls
to 0.766 and it catches 34% at the operating point.

Arm B is the result that shaped the design. Handing the same supervised model
the attested provenance fields moves recall from 0.344 to 0.355, which is
nothing. A model whose labels never contained the pattern does not learn to use
the evidence. So the defense cannot be supervised.

Arm G is the answer: novelty detection calibrated on legitimate traffic, ORed
with nine consent invariants that use no fraud labels at all. Treatment AUC
0.984 and recall 0.628 at a 0.7% alert rate, on attack families it has never
seen. D and F alone are both worse and they fail on disjoint vectors, which is
why the combiner is a rank-max rather than an average.

Per-vector, arm A is not merely worse, it is blind on exactly the attacks the
taxonomy predicted would be invisible at the network: AGH-01 checkout injection
0.00, AGH-07 transactional email injection 0.00, MND-02 cart mandate
substitution 0.00, MND-04 sub-cap structuring 0.00, MND-07 recurring hijack
0.00. Arm G takes those to 1.00, 1.00, 1.00, 1.00 and 0.71. The reverse also
holds: XRL-06 mule networks are caught by A at 1.00 and missed by G, which is
why the deployment shape is an OR of both, not a replacement.

## Coevolution result

`python experiments/coevolution.py`: 50 genomes per vector, 8 rounds, mutation
inside the declared taxonomy ranges, selection on evading arm G at the fixed
operating point.

Evasion climbs with rounds for most vectors. AGH-01 goes from 0.00 evasion in
round 0 to 0.94 by round 7. AGH-03 goes 0.48 to 0.88. Some vectors never evade
at all: AGH-07, IDS-07, MND-01, MND-02, MND-04 and XRL-04 stay at 0.00 across
every round, because the invariant they violate is definitional rather than
statistical. You cannot tune a genome into not having mutated the payee.

That split is the useful finding. Statistical detection erodes under adaptation;
invariant checks do not, because the attack has to stop being the attack in
order to pass them.

Recalibrating arm G on fresh benign traffic recovers detection on some evolved
populations and not others. Reported per vector in `results/coevolution.json`,
not smoothed over.

Every implemented vector's `difficulty` in the taxonomy is now the measured
round-7 evasion rate, with the original hand-set prior preserved as
`difficulty_prior`. Several priors were badly wrong: AGH-07 was guessed at 0.70
and measures 0.00, AGH-02 was guessed at 0.70 and measures 1.00.

## Honest limitations

Per-vector test counts in the headline run are small, between 4 and 58 records.
Vector-level recalls are directional, not precise. The arm-level numbers are
well powered; the per-vector table is not.

Arm E, the supervised oracle with treatment in training, reaches 0.9996 AUC.
That is an upper reference, and it also says the generators remain more
separable than real fraud would be once you are allowed to train on it.

The simulator has no settlement or fulfilment clock, so refund abuse (XRL-01)
and merchant bust-out (XRL-05) are approximated on the authorization record
rather than modelled properly. Recorded in `open_items` in `auth_record.yaml`.

## Status

Built: 29 of 29 vectors declared `implemented`, plus 3 benign generators.
13 taxonomy vectors remain `stub` by design.

Done: Identify, Generate, Defend, coevolution loop, web prototype.
Remaining: submission deck, git history, final reproducibility pass.
