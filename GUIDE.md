# ARTS engineering guide

Read this before touching the code. Sections 1 to 3 are the current state.
Sections 4 to 8 are the conventions and the bugs already paid for. Section 9 is
what is left.

Project: ARTS (Agentic Red Team Simulator), an entry for the Mastercard
Innovation Challenge at GFF 2026. Submission closes 31 August 2026. Three
artifacts are required: a runnable repo, a walkthrough deck, and a working web
prototype. Judged on diversity of attacks identified, fidelity of simulation,
detection efficacy, novelty, and real-world feasibility.

---

## 1. Status at a glance

| Item | State |
|---|---|
| Taxonomy, 42 vectors, 5 families | done, v0.3.0 with measured difficulty |
| Auth record schema with vantage model | done |
| Generator contract and population builder | done |
| 29 attack generators, 3 benign | done, smoke test passes |
| Featurizer, one per view | done |
| Seven-arm headline experiment | done, `results/headline.json` |
| Coevolution loop | done, `results/coevolution.json` |
| Walkthrough deck, 14 slides | done, `deck/ARTS_walkthrough.pptx` |
| Web prototype | done, all five panels verified end to end |
| Git history | done, initial commit `f95c393`, 21 files |
| Submission upload | **not started, and it is the only thing left** |

---

## 2. What the system claims, with the numbers that back it

Agentic payment fraud produces authorizations that are cryptographically valid,
mandate-compliant, fast, and approved. The evidence that would expose the attack
lives inside the agent platform and never crosses the payment network.

200,000 episodes, 29 attack generators, grouped split on `campaign_id`,
threshold pinned at a 0.5% alert rate on legitimate traffic and calibrated on a
held-out benign slice. Treatment is 21 agentic vectors that never appear in
training. Run size is configurable: `ARTS_EPISODES=200000 python
experiments/headline.py`.

| arm | view | control AUC | treatment AUC | treatment recall | alert |
|---|---|---|---|---|---|
| A supervised | v_network | 0.997 | 0.877 | 0.124 | 0.0053 |
| B supervised | v_attested | 0.999 | 0.799 | 0.124 | 0.0052 |
| C novelty | v_network | 0.838 | 0.898 | 0.458 | 0.0054 |
| D novelty | v_attested | 0.800 | 0.960 | 0.604 | 0.0051 |
| E oracle | v_attested | 0.998 | 1.000 | 1.000 | 0.0054 |
| F invariants | v_attested | 0.500 | 0.712 | 0.424 | 0.0009 |
| G hybrid, D or F | v_attested | 0.800 | 0.963 | 0.713 | 0.0051 |

Three things to keep straight when presenting this.

Arm A is not bad. It is 0.997 on the fraud it was built for. On agentic fraud it
catches 12.4%, and per vector it is at exactly 0.00 on eighteen of the
twenty-one. Blind, not degraded.

Arm B is the negative result and it must stay in. The attested fields leave
recall at exactly 0.124, identical to four decimals, because its labels never
taught it what those fields mean. Do not weaken this arm to simplify the story;
it is what makes arm G credible.

XRL-06 mule networks are caught by A at 1.00 and missed by G entirely. The
deployment shape is an OR of both detectors, never a replacement.

Coevolution, 50 genomes per vector over 8 generations, splits the vectors in
two. AGH-01 climbs from 0.00 evasion to 0.94, AGH-03 from 0.48 to 0.88. AGH-07,
IDS-07, MND-01, MND-02, MND-04 and XRL-04 never evade once in any round, because
the invariant they violate is definitional rather than statistical.

---

## 3. Layout and commands

```
schema/taxonomy.yaml        Identify. 42 vectors, the attack genome, measured difficulty.
schema/auth_record.yaml     Wire format. ISO 8583 core plus agentic extensions, vantage-tagged.
arts/core.py                Record model, validation, vantage projection, generator contract.
arts/generators.py          29 attack generators, 3 benign.
arts/features.py            One featurizer, applied per view.
experiments/headline.py     Seven-arm detection experiment.
experiments/coevolution.py  Adversarial genome evolution against arm G.
web/app.py, web/index.html  FastAPI service plus single-page prototype.
deck/build_deck.js          Regenerates the deck from the results JSON.
tests/smoke.py              Correctness gate.
results/                    headline.json, coevolution.json.
```

```bash
pip install -r requirements.txt
python tests/smoke.py                   # must print PASS
python experiments/headline.py          # ~4 min, writes results/headline.json
python experiments/coevolution.py       # writes results/coevolution.json
python -m uvicorn web.app:app --reload  # prototype on http://127.0.0.1:8000
node deck/build_deck.js                 # rebuilds the deck from current results
```

If `tests/smoke.py` fails, stop. Every number downstream is meaningless.

---

## 4. Core concepts

**Vantage.** Every field in `auth_record.yaml` carries a `vantage`: `network`,
`issuer`, `merchant`, `agent_platform`, or `ground_truth`. Fields marked
`attestable: true` are non-network fields an attestation or mandate extension
could plausibly carry without redesigning the rails.

**Views.** `v_network` (69 fields), `v_attested` (111), `v_omniscient` (112).
Generators emit whole records carrying every vantage. Projection happens once,
in `project()`, at experiment time. No generator decides what a detector sees.
This is the experiment; do not route around it.

**Genome.** The `parameters` block of a taxonomy vector. `sample_params` draws
from the declared ranges, `check_params` fails the build on anything outside
them. The taxonomy is the source of truth, the generator is not.

**Campaign.** One attack episode, possibly many correlated records under one
`campaign_id`. All splits group on it. Splitting on `txn_id` leaks.

**prevalence vs expected_records.** `prevalence` is a per-episode weight,
`fraud_rate` is a record-level target. `expected_records` converts between them.
Measure it, do not guess.

**Ratio convention (v0.2.0 onward).** Anything ending in `_ratio`, `_multiple`
or `_multiplier` is a multiplier where 1.0 means unchanged. Fractions of a
stated bound keep fraction semantics and are deliberately not suffixed.

**Difficulty (v0.3.0 onward).** `difficulty` is now a measured round-7 evasion
rate. The hand-set prior survives as `difficulty_prior`. If you rerun
coevolution, rerun the difficulty patch too or the two disagree.

Amounts are integer minor units. Timestamps are RFC3339 UTC strings. Durations
carry an explicit unit suffix in the field name.

---

## 5. Adding a generator

All 29 declared vectors are built. 13 remain `status: stub` by design. If you
promote one, it needs a taxonomy entry first, then:

```python
@register
class MyAttack(Generator):
    """XRL-05. One line on what the attack does, then two on what it looks
    like on v_network specifically, because that is what a reviewer checks."""

    vector_id = "XRL-05"
    prevalence = 2.0
    expected_records = 4.0     # measure it over 1000 runs, do not guess

    def constraints(self, g): return True    # reject implausible genomes, never clamp
    def emit(self, ctx, g, campaign_id): ...
```

Rules, ordered by how badly breaking each one hurts:

1. Emit whole records. Populate `agent_platform` and `merchant` fields even
   though no deployable view shows them.
2. Every attack must authorize cleanly wherever the real attack would. Start
   from `base_record` and change only what the attack changes. The smoke test
   fails the build if treatment approval drops below 90%.
3. Use the genome for every knob. The coevolution loop can only mutate what is
   declared.
4. Set `expected_records` by measuring.
5. Cap fan-out in a named class constant with a comment. Silent truncation reads
   as full coverage.
6. One campaign, one vector.

Benign generators subclass `BenignGenerator`. BEN-01 is the hard negative and
the most important object in the repo: it shares channel, token type,
attestation status and speed with every agentic attack. When you add a benign
generator, ask which feature it makes useless and whether that feature was
carrying an unearned win.

---

## 6. The featurizer

`arts/features.py` never assumes a field is present. It checks the projected
record; if the field is absent the feature is absent from that view's matrix.
That is what makes the view comparison honest. Add features inside `_derived`,
guarded by `has("field_name")`, and never read a field the guard did not confirm.

Velocity features are prior-only, walking the stream in timestamp order. The
one-hot vocabulary is fit on train and frozen, with unseen categories falling
into `__oov__`.

---

## 7. Bugs already paid for. Do not reintroduce them

1. **Threshold ties.** Supervised models pile benign scores on one identical
   near-zero value, so a 99.5th percentile cut with `>=` flags every tied row.
   Arm A once reported a 44% alert rate while claiming 0.5%. Use
   `pick_threshold` and compare with strict `>`.
2. **Calibrating on training rows.** The model memorised them. Thresholds come
   from the held-out calibration split.
3. **Ranking inside each scored batch.** A rank computed within the test array
   is not comparable to one from the calibration array. Both hybrid components
   go through an ECDF fitted once on calibration benign traffic.
4. **Rank-averaging the hybrid.** Novelty and invariants catch disjoint vectors,
   so averaging halves whichever is firing. Use rank-max with a novelty
   tie-break.
5. **YAML flow mappings cannot contain block scalars.** `- {name: x, desc: >}`
   does not parse.
6. **Record-level vs episode-level fraud rate.** See `expected_records`.

---

## 8. The invariants

Nine consent invariants live in `experiments/headline.py`: mandate hash
mismatch, charged over consented, intent-to-cart distance, payee mutated by
ingested content, lookalike of an allowlisted descriptor, amount parked just
under the cap, mandate replayed after expiry, sub-agent executed instead of the
enrolled one, OTP consumed by a different session.

A new invariant must be label-free and explainable in one sentence to a fraud
analyst. If you cannot state which contractual property it checks, it is a
learned feature and belongs in the featurizer.

---

## 9. What is left

### R1. Submit (the only blocking item)

Upload the repo, `deck/ARTS_walkthrough.pptx` and the prototype through the
Writeups section before 31 August 2026. Draft work left unsubmitted is not
judged.

### Verified, for the record

The prototype has now been run end to end. All five panels work: taxonomy
explorer, live generation, two-panel verdict, arm comparison, coevolution
curves. AGH-01 and MND-02 both pass arm A on `v_network` and are flagged by arm
G with the fired invariants named on screen. BEN-01 is clean on both. Git is
initialised with everything committed. `requirements.txt` now includes fastapi
and uvicorn, which were missing.

Note for anyone running git in this folder: the mount reports
`unable to unlink ... Operation not permitted` warnings on `.git` temp files.
The commits succeed anyway. Verify with `git log --oneline` rather than trusting
the warning text.

### Optional, only if time remains

Promote some of the 13 stub vectors. XRL-01 and XRL-05 need a settlement-clock
record type that does not exist yet, recorded in `open_items` in
`auth_record.yaml`. Do not fake them on the authorization record.

Per-vector test counts now run from 26 to 406 records, which is adequate for
arm-level claims and thin for the smallest vectors. Raising `ARTS_EPISODES`
further would firm those up.

---

## 10. House style

Comments explain why, not what. If a line encodes a decision that cost an hour
to find, write the reason down.

No em dashes in prose or comments.

When a result looks too good, say so in the same breath as reporting it. Arm E
at 0.9996 is reported alongside the note that it means the generators remain
more separable than real fraud. A reviewer who finds a problem you already
flagged trusts the rest. Every number in the deck comes from a committed script
with a fixed seed, and `node deck/build_deck.js` regenerates the charts from
`results/*.json`, so the deck cannot drift from the code.
