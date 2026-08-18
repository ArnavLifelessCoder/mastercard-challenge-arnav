"""
Feature engineering, one featurizer, many views.

The featurizer never asks for a field by assumption. It checks whether the
projected record carries it, and if not the feature is simply absent from that
view's matrix. That is what makes the view comparison honest: the same code
produces a 40-something column matrix on v_network and a 60-something column
matrix on v_attested, and the difference is exactly the stranded evidence.

Two rules that matter more than the feature list:

  1. Velocity features are computed prior-only, walking the record stream in
     timestamp order. A count that includes the current or future transactions
     leaks, and leaked velocity is the classic way a fraud model looks great
     offline and dies in production.
  2. The one-hot vocabulary is fit on train and frozen. Categories only seen at
     test time fall into an explicit `__oov__` column rather than silently
     shifting every downstream index.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Iterable, Sequence

import numpy as np

CATEGORICALS = {
    "channel": 4,
    "token_type": 4,
    "auth_type": 5,
    "agent_attestation_status": 5,
    "threeds_indicator": 6,
    "cvv_result": 5,
    "avs_result": 5,
    "sca_exemption": 7,
    "payee_mutation_source": 8,
    "tool_server_trust": 5,
    "acquisition_channel": 7,
    "mcc": 12,
    "source_geo_country": 8,
}

VELOCITY_WINDOWS = (3600, 86400)  # seconds


def _ts(v: Any) -> float:
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, str):
        return datetime.fromisoformat(v).timestamp()
    return 0.0


def _cos_distance(a: Sequence[float] | None, b: Sequence[float] | None) -> float | None:
    if not a or not b or len(a) != len(b):
        return None
    dot = sum(x * y for x, y in zip(a, b))
    return 1.0 - max(-1.0, min(1.0, dot))


def _edit_distance(a: str, b: str, cap: int = 12) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return min(prev[-1], cap)


def _log1p(x: float | None) -> float:
    return math.log1p(max(0.0, float(x))) if x is not None else 0.0


class Featurizer:
    """Fit the vocabulary and the field availability on train, apply anywhere."""

    def __init__(self) -> None:
        self.vocab: dict[str, list[str]] = {}
        self.available: set[str] = set()
        self.names: list[str] = []
        self._fitted = False

    # -- derived scalars ---------------------------------------------------

    def _derived(self, r: dict[str, Any]) -> dict[str, float]:
        d: dict[str, float] = {}
        has = self.available.__contains__

        amt = float(r.get("amount_minor") or 0)
        d["log_amount"] = _log1p(amt)

        if has("consent_amount_minor"):
            c = float(r.get("consent_amount_minor") or 0)
            d["amount_over_consent"] = amt / c if c > 0 else 1.0
        if has("mandate_per_txn_cap_minor"):
            cap = float(r.get("mandate_per_txn_cap_minor") or 0)
            d["cap_proximity"] = min(amt / cap, 4.0) if cap > 0 else 0.0
            d["just_under_cap"] = 1.0 if cap > 0 and 0.85 <= amt / cap <= 1.0 else 0.0
        if has("cumulative_captured_minor") and has("consent_amount_minor"):
            cum = float(r.get("cumulative_captured_minor") or 0)
            c = float(r.get("consent_amount_minor") or 0)
            d["cumulative_over_consent"] = cum / c if c > 0 else 0.0
        if has("series_baseline_amount_minor"):
            b = float(r.get("series_baseline_amount_minor") or 0)
            d["amount_over_series_baseline"] = amt / b if b > 0 else 0.0

        # mandate integrity: needs the agent-side consent hash, so this feature
        # exists on v_attested and simply is not there on v_network
        if has("consent_recorded_hash") and has("mandate_hash"):
            mh, ch = r.get("mandate_hash"), r.get("consent_recorded_hash")
            d["mandate_hash_mismatch"] = 1.0 if (mh and ch and mh != ch) else 0.0

        if has("intent_text_embedding") and has("cart_text_embedding"):
            cd = _cos_distance(r.get("intent_text_embedding"), r.get("cart_text_embedding"))
            d["intent_cart_distance"] = cd if cd is not None else 0.0
            d["intent_cart_distance_missing"] = 0.0 if cd is not None else 1.0

        if has("page_visible_text_hash") and has("page_extracted_text_hash"):
            pv, pe = r.get("page_visible_text_hash"), r.get("page_extracted_text_hash")
            d["page_hash_mismatch"] = 1.0 if (pv and pe and pv != pe) else 0.0

        if has("advertised_amount_minor"):
            adv = float(r.get("advertised_amount_minor") or 0)
            d["auth_over_advertised"] = amt / adv if adv > 0 else 1.0

        # descriptor aliasing: both halves are on the wire today
        if has("merchant_descriptor") and has("mandate_allowlist_descriptors"):
            desc = (r.get("merchant_descriptor") or "").upper()
            allow = r.get("mandate_allowlist_descriptors") or []
            if desc and allow:
                dists = [_edit_distance(desc, a.upper()) for a in allow]
                best = min(dists)
                d["descriptor_min_edit"] = float(best)
                d["descriptor_exact_allowlist"] = 1.0 if best == 0 else 0.0
                d["descriptor_near_miss"] = 1.0 if 1 <= best <= 4 else 0.0
            else:
                d["descriptor_min_edit"] = 12.0
                d["descriptor_exact_allowlist"] = 0.0
                d["descriptor_near_miss"] = 0.0

        if has("payee_mutation_source"):
            src = r.get("payee_mutation_source") or "none"
            d["payee_mutated_by_content"] = 1.0 if src not in ("none", "user_utterance") else 0.0
        if has("user_event_within_mutation_window"):
            d["user_event_in_window"] = 1.0 if r.get("user_event_within_mutation_window") else 0.0
        if has("memory_write_to_use_latency_hours"):
            d["log_memory_latency_h"] = _log1p(r.get("memory_write_to_use_latency_hours"))

        for f in (
            "user_confirmation_events",
            "user_interaction_events",
            "session_objective_drift",
            "injection_classifier_score",
            "declared_vs_executed_param_diff",
            "delegation_depth",
            "mandate_use_count",
            "series_sequence",
            "merchant_dispute_rate_bps",
        ):
            if has(f):
                v = r.get(f)
                d[f] = float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0

        for f, name in (
            ("cart_build_to_submit_ms", "log_cart_to_submit_ms"),
            ("time_since_last_user_event_ms", "log_since_user_event_ms"),
            ("merchant_tenure_days", "log_merchant_tenure_d"),
            ("rtt_ms", "log_rtt_ms"),
            ("stepup_response_latency_ms", "log_stepup_latency_ms"),
        ):
            if has(f):
                d[name] = _log1p(r.get(f))

        if has("consent_timestamp"):
            ct = _ts(r.get("consent_timestamp"))
            d["log_consent_age_s"] = _log1p(_ts(r.get("timestamp_utc")) - ct) if ct else 0.0
        if has("consent_expiry"):
            ce = _ts(r.get("consent_expiry"))
            d["consent_expired"] = 1.0 if ce and _ts(r.get("timestamp_utc")) > ce else 0.0
        if has("otp_issued_session_id") and has("otp_consumed_session_id"):
            a, b = r.get("otp_issued_session_id"), r.get("otp_consumed_session_id")
            d["otp_session_mismatch"] = 1.0 if (a and b and a != b) else 0.0
        if has("terminal_agent_id") and has("agent_id"):
            d["terminal_agent_differs"] = 1.0 if r.get("terminal_agent_id") != r.get("agent_id") else 0.0
        if has("device_first_seen"):
            df = _ts(r.get("device_first_seen"))
            d["log_device_age_s"] = _log1p(_ts(r.get("timestamp_utc")) - df) if df else 0.0

        ts = _ts(r.get("timestamp_utc"))
        d["hour_of_day"] = (ts % 86400) / 3600.0 if ts else 0.0
        return d

    # -- velocity ----------------------------------------------------------

    def _velocity(self, records: list[dict[str, Any]]) -> list[dict[str, float]]:
        """Prior-only counts. Walks in timestamp order and never looks ahead."""
        key_field = "token_id" if "token_id" in self.available else None
        out: list[dict[str, float]] = [dict() for _ in records]
        if key_field is None:
            return out
        order = sorted(range(len(records)), key=lambda i: _ts(records[i].get("timestamp_utc")))
        hist: dict[str, deque] = defaultdict(deque)
        merch: dict[str, deque] = defaultdict(deque)
        for i in order:
            r = records[i]
            k = r.get(key_field) or "__none__"
            t = _ts(r.get("timestamp_utc"))
            q = hist[k]
            while q and t - q[0] > max(VELOCITY_WINDOWS):
                q.popleft()
            f = out[i]
            for w in VELOCITY_WINDOWS:
                f[f"txn_prior_{w}s"] = float(sum(1 for x in q if t - x <= w))
            f["log_since_prev_txn_s"] = _log1p(t - q[-1]) if q else _log1p(86400 * 30)
            mq = merch[k]
            while mq and t - mq[0][0] > 3600:
                mq.popleft()
            f["distinct_merchants_prior_1h"] = float(len({m for _, m in mq}))
            q.append(t)
            mq.append((t, r.get("merchant_id")))
        return out

    # -- fit / transform ---------------------------------------------------

    def fit(self, records: list[dict[str, Any]]) -> "Featurizer":
        self.available = set()
        for r in records[: min(len(records), 5000)]:
            self.available.update(r.keys())

        self.vocab = {}
        for col, topk in CATEGORICALS.items():
            if col not in self.available:
                continue
            counts: dict[str, int] = defaultdict(int)
            for r in records:
                v = r.get(col)
                if isinstance(v, str):
                    counts[v] += 1
            top = sorted(counts, key=lambda k: -counts[k])[:topk]
            self.vocab[col] = top + ["__oov__"]

        probe = self._matrix(records[: min(len(records), 200)], names_only=True)
        self.names = probe
        self._fitted = True
        return self

    def _matrix(self, records: list[dict[str, Any]], names_only: bool = False):
        vel = self._velocity(records)
        rows: list[dict[str, float]] = []
        for r, v in zip(records, vel):
            d = self._derived(r)
            d.update(v)
            for col, vocab in self.vocab.items():
                val = r.get(col)
                val = val if isinstance(val, str) and val in vocab else "__oov__"
                for cand in vocab:
                    d[f"{col}={cand}"] = 1.0 if cand == val else 0.0
            rows.append(d)
        names = sorted({k for d in rows for k in d})
        if names_only:
            return names
        return rows, names

    def transform(self, records: list[dict[str, Any]]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("Featurizer.transform called before fit")
        rows, _ = self._matrix(records)
        X = np.zeros((len(rows), len(self.names)), dtype=np.float32)
        index = {n: i for i, n in enumerate(self.names)}
        for i, d in enumerate(rows):
            for k, v in d.items():
                j = index.get(k)
                if j is not None:
                    X[i, j] = v
        return X

    def fit_transform(self, records: list[dict[str, Any]]) -> np.ndarray:
        return self.fit(records).transform(records)
