"""
Headline experiment: four arms.

The naive version of this experiment does not work, and it is worth saying why
because the fix is the actual contribution.

Naive version: train a supervised detector on classical fraud using today's
authorization fields, show it fails on agentic fraud, then hand the same
supervised detector the attested provenance fields and show it recovers. The
first half works. The second half cannot work, and the reason is structural: a
supervised model trained only on classical attacks has never seen a single
example where intent-to-cart distance or a consent hash mismatch corresponded to
fraud, so it never learns to use those columns. Giving a model better evidence
does not help if its labels never taught it what the evidence means.

So the claim has to be sharper. Agentic fraud is not a new pattern to be learned
from past fraud. It is a violation of an invariant that, today, nobody can check.
The defense is therefore not "the same model with more columns", it is a
novelty detector calibrated on legitimate traffic alone, which flags departures
from what a well-formed agentic authorization looks like. That detector needs no
labelled agentic fraud, which matters because in the real world there is barely
any yet.

Arms:
  A  supervised, v_network      trained on benign + control. The incumbent.
  B  supervised, v_attested     same labels, better evidence. Expected to help
                                little, and saying so is the point.
  C  novelty, v_network         IsolationForest fit on benign only.
  D  novelty, v_attested        same, with provenance. The proposed defense.
  E  supervised oracle          treatment included in training. Upper reference,
                                not a deployable claim, shown so nobody thinks
                                the gap is unreachable.

Protocol notes:
  split         grouped on campaign_id, so correlated episode records never
                straddle train and test.
  calibration   the alert threshold is set on a benign slice held out of
                training, never on the training rows themselves. Calibrating on
                train benign understates the alert rate badly, because the model
                has memorised those rows.
  operating pt  recall is read at a fixed 0.5% alert rate on legitimate traffic.

Run: python experiments/headline.py
"""

from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

from arts import generators  # noqa: F401  registration side effect
from arts.core import PopulationConfig, Schema, Taxonomy, build_population, project
from arts.features import Featurizer

CONTROL = {"CGA-01", "CGA-03", "CGA-04", "CGA-05", "CGA-06", "CGA-08", "CGA-09"}
TREATMENT = {
    "AGH-01", "AGH-02", "AGH-03", "AGH-04", "AGH-07", "AGH-09",
    "MND-01", "MND-02", "MND-03", "MND-04", "MND-05", "MND-07",
    "IDS-01", "IDS-02", "IDS-03", "IDS-04", "IDS-05", "IDS-07",
    "XRL-01", "XRL-03", "XRL-04", "XRL-06",
}
ALERT_RATE = 0.005
N_EPISODES = 60_000
SEED = 17


def grouped_split(records, fracs=(0.6, 0.15, 0.25), seed=SEED):
    """Train / calibration / test, split on campaign_id."""
    rng = random.Random(seed)
    campaigns = sorted({r["campaign_id"] for r in records})
    rng.shuffle(campaigns)
    n = len(campaigns)
    a, b = int(n * fracs[0]), int(n * (fracs[0] + fracs[1]))
    sets = (set(campaigns[:a]), set(campaigns[a:b]), set(campaigns[b:]))
    out = ([], [], [])
    for r in records:
        for i, s in enumerate(sets):
            if r["campaign_id"] in s:
                out[i].append(r)
                break
    return out


def pick_threshold(scores: np.ndarray, rate: float) -> float:
    """Smallest t with alert rate at or under target, using strict greater-than.

    A plain quantile is wrong here. Supervised models pile most benign scores on
    an identical near-zero value, so the 99.5th percentile lands exactly on that
    pile and a >= comparison then flags every tied row. That is how arm A first
    reported a 44% alert rate while claiming a 0.5% threshold.
    """
    if len(scores) == 0:
        return 0.5
    uniq = np.unique(scores)
    lo, hi = 0, len(uniq) - 1
    best = float(uniq[-1])
    while lo <= hi:
        mid = (lo + hi) // 2
        t = float(uniq[mid])
        if float((scores > t).mean()) <= rate:
            best = t
            hi = mid - 1
        else:
            lo = mid + 1
    return best


def evaluate(scores, y, thr) -> dict:
    pos, neg = int(y.sum()), int((1 - y).sum())
    flagged = scores > thr
    tp = int(((y == 1) & flagged).sum())
    fp = int(((y == 0) & flagged).sum())
    recall = tp / pos if pos else float("nan")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    out = {
        "n": int(len(y)), "n_fraud": pos, "n_benign": neg,
        "recall": round(recall, 4), "precision": round(precision, 4), "f1": round(f1, 4),
        "benign_alert_rate": round(fp / neg, 5) if neg else float("nan"),
    }
    if pos and neg:
        out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
    return out


INVARIANTS = [
    # (feature name, comparison, threshold). Each is a property that must hold
    # for a well-formed agentic authorization. None of them is learned from
    # fraud labels, which is why they work on attacks nobody has seen yet.
    ("mandate_hash_mismatch", "gt", 0.5),      # submitted basket is not the consented one
    ("amount_over_consent", "gt", 1.02),       # charged more than consented
    ("intent_cart_distance", "gt", 0.35),      # cart does not match what the user asked for
    ("payee_mutated_by_content", "gt", 0.5),   # payee changed by ingested content, not the user
    ("descriptor_near_miss", "gt", 0.5),       # lookalike of an allowlisted merchant
    ("just_under_cap", "gt", 0.5),             # amount parked immediately below the cap
    ("consent_expired", "gt", 0.5),            # mandate replayed outside its window
    ("terminal_agent_differs", "gt", 0.5),     # a sub-agent executed, not the enrolled one
    ("otp_session_mismatch", "gt", 0.5),       # code consumed by a different session
]


def invariant_score(X: np.ndarray, names: list[str]) -> np.ndarray:
    """Count violated invariants. No labels, no training, fully explainable."""
    idx = {n: i for i, n in enumerate(names)}
    s = np.zeros(X.shape[0], dtype=np.float32)
    for name, _, thr in INVARIANTS:
        j = idx.get(name)
        if j is not None:
            s += (X[:, j] > thr).astype(np.float32)
    return s


def _ecdf(reference: np.ndarray):
    """Percentile transform fitted on a reference sample.

    Ranking within each scored batch was the bug here: a rank computed inside
    the test array is not comparable to one computed inside the calibration
    array, so the calibrated threshold meant nothing. Both component scores are
    now mapped through an ECDF fitted once on calibration benign traffic.
    """
    ref = np.sort(np.asarray(reference, dtype=np.float64))
    n = max(len(ref), 1)
    return lambda x: np.searchsorted(ref, np.asarray(x, dtype=np.float64), side="right") / n


class Arm:
    def __init__(self, name, view, kind, train_filter):
        self.name, self.view, self.kind, self.train_filter = name, view, kind, train_filter
        self.fz = Featurizer()
        self.model = None
        self._e_nov = self._e_inv = lambda x: np.asarray(x, dtype=np.float64)
        self.thr = 0.0
        self.n_features = 0

    def _pr(self, rs, schema):
        return [project(r, self.view, schema) for r in rs]

    def fit(self, train, calib, schema):
        rows = [r for r in train if self.train_filter(r)]
        P = self._pr(rows, schema)
        self.fz.fit(P)
        X = self.fz.transform(P)
        self.n_features = len(self.fz.names)
        if self.kind == "rules":
            pass
        elif self.kind == "supervised":
            y = np.array([1 if r["label"] == "fraud" else 0 for r in rows])
            self.model = HistGradientBoostingClassifier(
                max_iter=300, learning_rate=0.08, max_leaf_nodes=31,
                l2_regularization=1.0, random_state=SEED)
            self.model.fit(X, y)
        elif self.kind in ("novelty", "hybrid"):
            self.model = IsolationForest(
                n_estimators=300, max_samples=4096, contamination="auto",
                random_state=SEED, n_jobs=-1)
            self.model.fit(X)
        # component ECDFs fitted on calibration benign, so scores are comparable
        # across batches
        cb = [r for r in calib if r["label"] == "benign"]
        if self.kind == "hybrid":
            Xc = self.fz.transform(self._pr(cb, schema))
            self._e_nov = _ecdf(-self.model.score_samples(Xc))
            self._e_inv = _ecdf(invariant_score(Xc, self.fz.names))
        s = self.score(cb, schema)
        self.thr = pick_threshold(s, ALERT_RATE)
        return self

    def score(self, records, schema) -> np.ndarray:
        X = self.fz.transform(self._pr(records, schema))
        if self.kind == "supervised":
            return self.model.predict_proba(X)[:, 1]
        if self.kind == "rules":
            return invariant_score(X, self.fz.names)
        nov = -self.model.score_samples(X)
        if self.kind == "novelty":
            return nov
        # hybrid: rank-max, which behaves like an OR. Averaging was worse and
        # the reason is instructive: the two detectors catch disjoint vectors.
        # Invariants catch consent violations (AGH-01, AGH-09, MND-02, MND-05),
        # novelty catches episode-shape attacks (IDS-05, MND-01). Averaging
        # halves whichever one is firing; max keeps it.
        rn = self._e_nov(nov)
        # tie-break inside an invariant-count plateau by novelty percentile,
        # otherwise the score is coarse and the threshold search undershoots the
        # alert budget, leaving recall on the table
        return np.maximum(rn, self._e_inv(invariant_score(X, self.fz.names))) + 1e-6 * rn


def main() -> int:
    schema, tax = Schema.load(), Taxonomy.load()
    print(f"building population: {N_EPISODES} episodes")
    records = list(build_population(
        PopulationConfig(n_episodes=N_EPISODES, fraud_rate=0.02, seed=SEED),
        schema=schema, taxonomy=tax))
    print(f"records: {len(records)}")
    print("mix:", dict(Counter(r.get("vector_id") or "BENIGN" for r in records).most_common()))

    train, calib, test = grouped_split(records)
    is_benign_or_control = lambda r: r["label"] == "benign" or r["vector_id"] in CONTROL  # noqa: E731
    is_benign = lambda r: r["label"] == "benign"  # noqa: E731

    test_control = [r for r in test if r["label"] == "benign" or r["vector_id"] in CONTROL]
    test_treatment = [r for r in test if r["label"] == "benign" or r["vector_id"] in TREATMENT]
    print(f"train={len(train)} calib={len(calib)} test={len(test)}  "
          f"test_control_fraud={sum(r['label']=='fraud' for r in test_control)} "
          f"test_treatment_fraud={sum(r['label']=='fraud' for r in test_treatment)}")

    arms = [
        Arm("A supervised v_network", "v_network", "supervised", is_benign_or_control),
        Arm("B supervised v_attested", "v_attested", "supervised", is_benign_or_control),
        Arm("C novelty    v_network", "v_network", "novelty", is_benign),
        Arm("D novelty    v_attested", "v_attested", "novelty", is_benign),
        Arm("E oracle     v_attested", "v_attested", "supervised", lambda r: True),
        Arm("F invariants v_attested", "v_attested", "rules", is_benign),
        Arm("G hybrid     v_attested", "v_attested", "hybrid", is_benign),
    ]

    results = {"config": {"n_episodes": N_EPISODES, "seed": SEED, "alert_rate": ALERT_RATE,
                          "control": sorted(CONTROL), "treatment": sorted(TREATMENT)},
               "arms": {}}

    for arm in arms:
        arm.fit(train, calib, schema)
        row = {"view": arm.view, "kind": arm.kind, "n_features": arm.n_features,
               "threshold": round(arm.thr, 6)}
        for label, subset in (("control", test_control), ("treatment", test_treatment)):
            s = arm.score(subset, schema)
            y = np.array([1 if r["label"] == "fraud" else 0 for r in subset])
            row[label] = evaluate(s, y, arm.thr)
        st = arm.score(test_treatment, schema)
        row["treatment_by_vector"] = {
            vid: {"n": len(idx), "recall": round(float((st[idx] > arm.thr).mean()), 4)}
            for vid in sorted(TREATMENT)
            if (idx := [i for i, r in enumerate(test_treatment) if r.get("vector_id") == vid])
        }
        results["arms"][arm.name] = row

        c, t = row["control"], row["treatment"]
        print(f"\n{arm.name}  feats={arm.n_features}")
        print(f"   control    AUC={c.get('roc_auc')}  PR={c.get('pr_auc')}  "
              f"recall={c['recall']}  alert={c['benign_alert_rate']}")
        print(f"   treatment  AUC={t.get('roc_auc')}  PR={t.get('pr_auc')}  "
              f"recall={t['recall']}  alert={t['benign_alert_rate']}")
        print("   by vector:", {k: v["recall"] for k, v in row["treatment_by_vector"].items()})

    out = ROOT / "results" / "headline.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 76)
    print(f"{'arm':26} {'ctrl AUC':>9} {'treat AUC':>10} {'treat recall':>13} {'alert':>8}")
    for name, r in results["arms"].items():
        print(f"{name:26} {r['control'].get('roc_auc', 0):>9} {r['treatment'].get('roc_auc', 0):>10} "
              f"{r['treatment']['recall']:>13} {r['treatment']['benign_alert_rate']:>8}")
    print("=" * 76)
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
