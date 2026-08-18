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

`python experiments/headline.py`: 200,000 episodes, 29 attack generators,
grouped split on `campaign_id`, threshold pinned at a 0.5% alert rate on
legitimate traffic and calibrated on a held-out benign slice. Treatment is 21
agentic vectors that never appear in training, control is 7 classical
GenAI-assisted vectors that do.

| arm | view | control AUC | treatment AUC | treatment recall | alert rate |
|---|---|---|---|---|---|
| A supervised | v_network | 0.997 | 0.877 | 0.124 | 0.0053 |
| B supervised | v_attested | 0.999 | 0.799 | 0.124 | 0.0052 |
| C novelty | v_network | 0.838 | 0.898 | 0.458 | 0.0054 |
| D novelty | v_attested | 0.800 | 0.960 | 0.604 | 0.0051 |
| E supervised oracle | v_attested | 0.998 | 1.000 | 1.000 | 0.0054 |
| F invariants only | v_attested | 0.500 | 0.712 | 0.424 | 0.0009 |
| G hybrid (D or F) | v_attested | 0.800 | 0.963 | 0.713 | 0.0051 |

Arm A is the incumbent, and it is excellent at what it was built for: 0.997 AUC
on classical fraud. On agentic fraud it never trained on, it catches 12.4% at
the same operating point. Per vector it is at exactly 0.00 on eighteen of the
twenty-one agentic vectors, including checkout injection, email injection, cart
mandate substitution, sub-cap structuring and memory poisoning. Not degraded,
blind.

Arm B is the result that shaped the design. Handing the same supervised model
the attested provenance fields leaves recall at exactly 0.124, unchanged to four
decimals. A model whose labels never contained the pattern does not learn to use
the evidence. So the defense cannot be supervised.

Arm G is the answer: novelty detection calibrated on legitimate traffic, ORed
with nine consent invariants that use no fraud labels at all. Treatment AUC
0.963 and recall 0.713 at a 0.51% alert rate, on attack families it has never
seen. D and F alone are both worse and they fail on disjoint vectors, which is
why the combiner is a rank-max rather than an average.

The counterweight matters: XRL-06 mule networks are caught by A at 1.00 and
missed by G entirely. The deployment shape is an OR of both detectors, never a
replacement.

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

Per-vector test counts run from 26 to 406 records. Adequate for the arm-level
claims, thin for the smallest vectors, so treat individual vector recalls
accordingly.

Arm E, the supervised oracle with treatment in training, reaches 1.000 AUC.
That is an upper reference, and it also says the generators remain more
separable than real fraud would be once you are allowed to train on it.

The simulator has no settlement or fulfilment clock, so refund abuse (XRL-01)
and merchant bust-out (XRL-05) are approximated on the authorization record
rather than modelled properly. Recorded in `open_items` in `auth_record.yaml`.

## Status

Built: 29 of 29 vectors declared `implemented`, plus 3 benign generators.
13 taxonomy vectors remain `stub` by design.

Done: Identify, Generate, Defend, coevolution loop, web prototype (verified end
to end), deck, git history.
Remaining: submission upload before 31 August.
