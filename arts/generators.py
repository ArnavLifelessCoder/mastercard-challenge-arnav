"""
Reference generators: the full build set plus a benign population.

Treatment (agentic):  AGH-01, AGH-02, AGH-03, AGH-04, AGH-07, AGH-09,
                      MND-01, MND-02, MND-03, MND-04, MND-05, MND-07,
                      IDS-01, IDS-02, IDS-03, IDS-04, IDS-05, IDS-07,
                      XRL-01, XRL-03, XRL-04, XRL-06
Control (classical):  CGA-01, CGA-03, CGA-04, CGA-05, CGA-06, CGA-08, CGA-09
Benign:               BEN-01 agentic shopping, BEN-02 human ecom, BEN-03 recurring

Every attack here is written to produce an approved, mandate-compliant, clean
looking authorization wherever the real attack would. If a generator makes fraud
easy to spot on v_network, that is a bug in the generator, not a property of the
attack.
"""

from __future__ import annotations

import math
import random
import uuid
from datetime import timedelta
from typing import Any

from .core import (
    BenignGenerator,
    Context,
    Generator,
    base_record,
    mark_fraud,
    register,
)

USD = 100  # minor units per dollar


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _unit(rng: random.Random, dim: int) -> list[float]:
    v = [rng.gauss(0, 1) for _ in range(dim)]
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def embedding_pair(rng: random.Random, cosine_distance: float, dim: int = 16) -> tuple[list[float], list[float]]:
    """Two unit vectors separated by approximately the requested cosine distance.

    Used for intent_text_embedding and cart_text_embedding. The whole AGH-01 and
    AGH-09 story is the distance between these two, so it has to be controllable
    rather than incidental.
    """
    d = min(max(cosine_distance, 0.0), 1.0)
    theta = math.acos(1.0 - d)
    u = _unit(rng, dim)
    w = _unit(rng, dim)
    dot = sum(a * b for a, b in zip(u, w))
    w = [b - dot * a for a, b in zip(u, w)]
    n = math.sqrt(sum(x * x for x in w)) or 1.0
    w = [x / n for x in w]
    v = [math.cos(theta) * a + math.sin(theta) * b for a, b in zip(u, w)]
    return [round(x, 6) for x in u], [round(x, 6) for x in v]


def _mutate_descriptor(rng: random.Random, s: str, edits: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789"
    out = list(s)
    for _ in range(edits):
        if not out:
            break
        op = rng.choice(["sub", "ins", "del"])
        i = rng.randrange(len(out))
        if op == "sub":
            out[i] = rng.choice(alphabet)
        elif op == "ins":
            out.insert(i, rng.choice(alphabet))
        elif len(out) > 1:
            out.pop(i)
    return "".join(out)


def _novel_merchant(rng: random.Random) -> str:
    return f"mid_{rng.randint(900000, 999999)}"


# ---------------------------------------------------------------------------
# TREATMENT: agentic
# ---------------------------------------------------------------------------


@register
class CheckoutInjection(Generator):
    """AGH-01. Hidden instruction on a checkout page inflates the cart.

    On v_network this is one approved agentic auth at a plausible amount. The
    only thing that separates it from BEN-01 is the intent to cart distance and
    the missing confirmation event, both of which are attestable, neither of
    which is on the wire today.
    """

    vector_id = "AGH-01"
    prevalence = 3.0
    expected_records = 1.0

    def constraints(self, g: dict[str, Any]) -> bool:
        # A fully specified payload that does not move the cart is not an attack.
        if g["payload_specificity"] > 0.7 and g["cart_value_ratio"] < 1.05:
            return False
        # Hiding the payload in visible text only works if it is vague enough to
        # read as page copy to a human.
        if g["injection_placement"] == "visible_text" and g["payload_specificity"] > 0.6:
            return False
        return True

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        intended = r["amount_minor"]
        r["consent_amount_minor"] = intended
        r["amount_minor"] = int(intended * g["cart_value_ratio"])

        drift = min(0.9, 0.15 + 0.5 * g["payload_specificity"] + 0.1 * (g["cart_value_ratio"] - 1.0))
        iv, cv = embedding_pair(ctx.rng, drift)
        r["intent_text_embedding"], r["cart_text_embedding"] = iv, cv
        r["intent_id"] = uuid.UUID(int=ctx.rng.getrandbits(128)).hex[:12]
        r["intent_timestamp"] = r["consent_timestamp"]

        if g["confirmation_suppressed"]:
            r["user_confirmation_events"] = 0
        r["user_interaction_events"] = ctx.rng.randint(1, 3)
        r["cart_build_to_submit_ms"] = ctx.rng.randint(150, 2500)
        r["page_visible_text_hash"] = f"v{ctx.rng.getrandbits(48):012x}"
        r["page_extracted_text_hash"] = (
            r["page_visible_text_hash"]
            if g["injection_placement"] == "visible_text"
            else f"x{ctx.rng.getrandbits(48):012x}"
        )
        r["injection_classifier_score"] = round(
            min(0.99, 0.25 + 0.6 * g["payload_specificity"] * (0.5 if g["injection_placement"] == "visible_text" else 1.0)), 4
        )
        # mandate still validates: the inflated cart is what got signed
        r["consent_recorded_hash"] = r["mandate_hash"]
        succeeded = ctx.rng.random() < max(0.05, g["agent_model_susceptibility"] * 4)
        return [mark_fraud(r, r["amount_minor"] - intended, succeeded)]


@register
class GoalDrift(Generator):
    """AGH-09. Many small nudges across a long session displace the objective.

    Emits the whole session as one campaign so a row-level split cannot leak it.
    """

    vector_id = "AGH-09"
    prevalence = 2.0
    expected_records = 1.0

    def constraints(self, g: dict[str, Any]) -> bool:
        return g["turns_to_drift"] * g["per_turn_nudge_magnitude"] >= 0.25

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        total_drift = min(0.95, g["turns_to_drift"] * g["per_turn_nudge_magnitude"])
        r = base_record(ctx, agentic=True)
        iv, cv = embedding_pair(ctx.rng, total_drift)
        r["intent_text_embedding"], r["cart_text_embedding"] = iv, cv
        r["session_turn_index"] = int(g["turns_to_drift"])
        r["session_objective_drift"] = round(total_drift, 4)
        r["intent_category"] = "electronics"
        if g["category_drift"]:
            r["mcc"] = ctx.rng.choice(["5732", "5944", "6051", "5967"])
            r["merchant_id"] = _novel_merchant(ctx.rng)
            r["merchant_descriptor"] = "GENERAL GOODS ONLINE"
        r["amount_minor"] = int(r["amount_minor"] * (1.0 + total_drift))
        r["consent_amount_minor"] = r["amount_minor"]
        r["user_confirmation_events"] = 1  # the user did confirm, on a drifted objective
        return [mark_fraud(r, r["amount_minor"])]


@register
class MemoryPoisoning(Generator):
    """MND-01. A payee routing fact planted days earlier fires on a normal trigger.

    The strongest vector in the set. At authorization time nothing is unusual:
    established relationship, expected amount band, valid mandate. The evidence
    is a memory write that happened weeks ago inside the agent.
    """

    vector_id = "MND-01"
    prevalence = 2.0
    expected_records = 1.0

    def constraints(self, g: dict[str, Any]) -> bool:
        # A same-day write is just a hijack, not the dormancy typology.
        return not (g["dormancy_days"] < 2 and g["value_at_risk_usd"] > 100_000)

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["amount_minor"] = int(g["value_at_risk_usd"] * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        r["mcc"] = "4829"
        r["merchant_descriptor"] = "SUPPLIER PAYMENT"
        r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
        r["payee_first_seen"] = (ctx.now - timedelta(days=int(g["dormancy_days"]))).isoformat(timespec="milliseconds")
        r["payee_mutated_at"] = r["payee_first_seen"]
        r["payee_mutation_source"] = (
            "user_utterance" if g["write_channel"] == "user_utterance" else g["write_channel"]
        )
        r["memory_write_to_use_latency_hours"] = round(g["dormancy_days"] * 24.0, 2)
        r["user_event_within_mutation_window"] = g["write_channel"] == "user_utterance"
        # nothing else looks wrong: the agent is attested, the mandate is fresh
        r["user_confirmation_events"] = 1
        r["user_interaction_events"] = ctx.rng.randint(2, 8)
        succeeded = g["write_channel"] != "user_utterance"
        return [mark_fraud(r, r["amount_minor"], succeeded)]


@register
class CartMandateSubstitution(Generator):
    """MND-02. The basket changes between consent and submission.

    hash_validation_bypassed is the interesting knob: when true, the on-the-wire
    mandate hash is recomputed and validates cleanly, so only the agent-side
    consent hash disagrees. That is the stranded-signal case in one field.
    """

    vector_id = "MND-02"
    prevalence = 2.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        consented = r["amount_minor"]
        r["consent_amount_minor"] = consented
        r["amount_minor"] = int(consented * g["value_uplift_ratio"])
        r["consent_recorded_hash"] = f"c{ctx.rng.getrandbits(48):012x}"
        if g["hash_validation_bypassed"]:
            r["mandate_hash"] = f"h{ctx.rng.getrandbits(48):012x}"  # valid, just not the consented basket
        else:
            r["mandate_hash"] = r["consent_recorded_hash"]
        if g["substitution_type"] == "merchant_swap":
            r["merchant_id"] = _novel_merchant(ctx.rng)
            r["merchant_descriptor"] = "FULFILMENT PARTNER"
        r["cart_build_to_submit_ms"] = int(g["time_to_substitution_ms"])
        iv, cv = embedding_pair(ctx.rng, min(0.8, 0.1 * g["value_uplift_ratio"]))
        r["intent_text_embedding"], r["cart_text_embedding"] = iv, cv
        return [mark_fraud(r, r["amount_minor"] - consented)]


@register
class AllowlistAliasing(Generator):
    """MND-05. A lookalike merchant satisfies mandate scope enforcement."""

    vector_id = "MND-05"
    prevalence = 2.0
    expected_records = 1.0

    def constraints(self, g: dict[str, Any]) -> bool:
        # Zero edit distance with matching MCC and matching acquirer is not an
        # attack, it is the allowlisted merchant.
        return not (g["descriptor_edit_distance"] == 0 and g["mcc_match"] and not g["acquirer_mismatch"])

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        allow = r.get("mandate_allowlist_descriptors") or ["KNOWN MERCHANT"]
        target = ctx.rng.choice(allow)
        r["merchant_descriptor"] = _mutate_descriptor(ctx.rng, target, int(g["descriptor_edit_distance"]))
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["merchant_tenure_days"] = int(g["merchant_tenure_days"])
        r["merchant_legal_name"] = f"NEWCO {ctx.rng.getrandbits(16):04x} LTD"
        r["merchant_tax_id"] = f"TX{ctx.rng.getrandbits(28):08x}"
        if not g["mcc_match"]:
            r["mcc"] = ctx.rng.choice(["7995", "6051", "5967"])
        if g["acquirer_mismatch"]:
            r["acquirer_bin"] = f"{ctx.rng.randint(500000, 599999)}"
        r["amount_minor"] = min(r["amount_minor"], r.get("mandate_per_txn_cap_minor", 50000))
        r["consent_amount_minor"] = r["amount_minor"]
        return [mark_fraud(r, r["amount_minor"])]


@register
class AgenticAccountTakeover(Generator):
    """IDS-05. Compromised agent transacts across many merchants in parallel.

    Every record is individually unremarkable and mandate compliant. The signal
    is the shape of the episode, which is why campaign_id grouping matters.
    """

    vector_id = "IDS-05"
    prevalence = 1.5
    expected_records = 41.0
    MAX_EMIT = 80  # equals the taxonomy ceiling, so nothing is silently dropped

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        n = min(int(g["merchant_fanout"]), self.MAX_EMIT)
        span = float(g["duration_minutes"])
        out = []
        for i in range(n):
            ts = ctx.now + timedelta(minutes=span * i / max(n, 1))
            r = base_record(ctx, agentic=True, ts=ts)
            r["merchant_id"] = _novel_merchant(ctx.rng)
            r["amount_minor"] = int(g["per_txn_amount_usd"] * USD * ctx.rng.uniform(0.8, 1.2))
            r["consent_amount_minor"] = r["amount_minor"]
            if ctx.rng.random() > g["mimics_user_history"]:
                r["mcc"] = ctx.rng.choice(["5732", "5944", "5967", "7995", "5411"])
            r["user_interaction_events"] = int(g["user_interaction_events"])
            r["user_confirmation_events"] = 1 if ctx.rng.random() < 0.2 else 0
            r["time_since_last_user_event_ms"] = ctx.rng.randint(60_000, 3_600_000)
            r["cart_build_to_submit_ms"] = ctx.rng.randint(80, 900)
            r["session_id"] = campaign_id  # one compromised session, many merchants
            out.append(mark_fraud(r, r["amount_minor"]))
        return out


# ---------------------------------------------------------------------------
# CONTROL: classical GenAI-assisted
# ---------------------------------------------------------------------------


@register
class PersonalisedPhishing(Generator):
    """CGA-03. Credential compromise then card-not-present use from novel geo.

    Leaves conventional tells on the wire, but probabilistically: some records
    come from the victim's own country, reuse the victim's device, or pass CVV.
    personalisation_depth controls how many tells survive. A near-miss fraction
    overlaps with benign travel, so the control AUC is not trivially 1.0.
    """

    vector_id = "CGA-03"
    prevalence = 4.0
    expected_records = 2.5

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        out = []
        # sophistication: higher personalisation_depth means more tells are suppressed
        depth = g["personalisation_depth"]
        for i in range(ctx.rng.randint(1, 4)):
            ts = ctx.now + timedelta(hours=g["time_to_use_hours"] + i * 0.4)
            r = base_record(ctx, agentic=False, ts=ts)
            r["merchant_id"] = _novel_merchant(ctx.rng)

            # amount: sophisticated attacks stay closer to normal spend
            if ctx.rng.random() < depth * 0.4:
                r["amount_minor"] = int(ctx.actor.typical_amount_minor * ctx.rng.uniform(0.8, 2.0))
            else:
                r["amount_minor"] = int(ctx.actor.typical_amount_minor * ctx.rng.uniform(2.0, 9.0))

            # geo: sometimes from victim's own country
            if ctx.rng.random() < depth * 0.35:
                r["source_geo_country"] = ctx.actor.issuer_country
                r["source_geo_lat"] = ctx.actor.home_lat + ctx.rng.uniform(-2, 2)
                r["source_geo_lon"] = ctx.actor.home_lon + ctx.rng.uniform(-2, 2)
                r["rtt_ms"] = ctx.rng.randint(8, 60)
            else:
                r["source_geo_country"] = ctx.rng.choice(["RO", "NG", "VN", "BR", "RU"])
                r["source_geo_lat"] = round(ctx.rng.uniform(-30, 60), 4)
                r["source_geo_lon"] = round(ctx.rng.uniform(-60, 130), 4)
                r["rtt_ms"] = ctx.rng.randint(120, 400)

            # device: sometimes reuse victim's own device
            if ctx.rng.random() < depth * 0.35:
                r["device_fingerprint_id"] = ctx.actor.device_fingerprint_id
            else:
                r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"

            # CVV/AVS: sometimes pass cleanly
            if ctx.rng.random() < depth * 0.3:
                r["cvv_result"] = "M"
            else:
                r["cvv_result"] = ctx.rng.choice(["M", "N", "P"])
            if ctx.rng.random() < depth * 0.25:
                r["avs_result"] = "Y"
            else:
                r["avs_result"] = ctx.rng.choice(["N", "U"])

            r["threeds_indicator"] = "none"
            approved = ctx.rng.random() < 0.55
            r["approved"] = approved
            r["response_code"] = "00" if approved else "05"
            if not approved:
                r["decline_reason"] = "do_not_honour"
            out.append(mark_fraud(r, r["amount_minor"], approved))
        return out


@register
class CardTestingSwarm(Generator):
    """CGA-06. Adaptive low-value probing across many BINs.

    Emission is capped well below bins_touched. Tells are probabilistic: some
    probes pass CVV, reuse existing BINs/devices, or use slightly higher amounts,
    so the control AUC is not trivially 1.0 from probe amount alone.
    """

    vector_id = "CGA-06"
    prevalence = 5.0
    expected_records = 59.0
    MAX_EMIT = 60

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        n = min(int(g["bins_touched"]), self.MAX_EMIT)
        adapt = g["adaptation_rate"]
        out = []
        decline_p = 0.85
        for i in range(n):
            ts = ctx.now + timedelta(seconds=60.0 * i / max(g["requests_per_minute"], 1))
            r = base_record(ctx, agentic=False, ts=ts)

            # amount: adapted probes occasionally try higher amounts to blend in
            if ctx.rng.random() < adapt * 0.25:
                r["amount_minor"] = max(100, int(ctx.rng.uniform(5, 30) * USD))
            else:
                r["amount_minor"] = max(1, int(g["probe_amount_usd"] * USD))

            # BIN: sometimes reuse a plausible existing BIN
            if ctx.rng.random() < adapt * 0.15:
                r["bin"] = ctx.actor.bin
            else:
                r["bin"] = f"{ctx.rng.randint(400000, 599999)}"

            r["token_id"] = f"tok_{ctx.rng.getrandbits(32):08x}"
            r["account_id"] = f"acct_probe_{ctx.rng.getrandbits(24):06x}"

            # merchant: adapted probes sometimes use known merchants
            if ctx.rng.random() < adapt * 0.2 and ctx.actor.known_merchants:
                r["merchant_id"] = ctx.rng.choice(ctx.actor.known_merchants)
            else:
                r["merchant_id"] = f"mid_{ctx.rng.randint(1, max(1, int(g['merchant_rotation']))):06d}"

            # device: adapted probes sometimes reuse the victim's device
            if ctx.rng.random() < adapt * 0.15:
                r["device_fingerprint_id"] = ctx.actor.device_fingerprint_id
            else:
                r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"

            # CVV: not always N, adapted probes may pass
            if ctx.rng.random() < adapt * 0.2:
                r["cvv_result"] = ctx.rng.choice(["M", "P"])
            else:
                r["cvv_result"] = "N"

            decline_p = max(0.15, decline_p - adapt * 0.02)
            approved = ctx.rng.random() > decline_p
            r["approved"] = approved
            r["response_code"] = "00" if approved else "05"
            if not approved:
                r["decline_reason"] = "invalid_card"
            out.append(mark_fraud(r, r["amount_minor"] if approved else 0, approved))
        return out


# ---------------------------------------------------------------------------
# BENIGN
# ---------------------------------------------------------------------------


@register
class BenignAgenticShopping(BenignGenerator):
    """BEN-01. A real agent completing a real purchase the user asked for.

    This is the hard negative. It shares the channel, the token type, the
    attestation status and the speed with every treatment vector. If the
    baseline detector separates fraud from this on v_network, check the
    generator before believing the result.
    """

    vector_id = "BEN-01"
    prevalence = 35.0
    expected_records = 1.3

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        out = []
        for i in range(ctx.rng.choices([1, 2, 3], weights=[0.75, 0.2, 0.05])[0]):
            r = base_record(ctx, agentic=True, ts=ctx.now + timedelta(minutes=3 * i))
            iv, cv = embedding_pair(ctx.rng, ctx.rng.uniform(0.0, 0.18))
            r["intent_text_embedding"], r["cart_text_embedding"] = iv, cv
            r["intent_id"] = uuid.UUID(int=ctx.rng.getrandbits(128)).hex[:12]
            r["intent_timestamp"] = r["consent_timestamp"]
            r["payee_mutation_source"] = "none"
            r["user_event_within_mutation_window"] = True
            r["memory_write_to_use_latency_hours"] = 0.0
            r["injection_classifier_score"] = round(ctx.rng.uniform(0.0, 0.2), 4)
            r["page_visible_text_hash"] = f"v{ctx.rng.getrandbits(48):012x}"
            r["page_extracted_text_hash"] = r["page_visible_text_hash"]
            r["time_since_last_user_event_ms"] = ctx.rng.randint(500, 45_000)
            # legitimate agents are fast too, which is the whole problem
            r["cart_build_to_submit_ms"] = ctx.rng.randint(400, 30_000)
            out.append(r)
        return out


@register
class BenignHumanEcom(BenignGenerator):
    """BEN-02. Human-initiated e-commerce.

    Includes occasional travel, AVS failures, and new devices so that the benign
    population overlaps with control attack tells. Without this overlap the
    control AUC is artificially 1.0 and a judge reads it as rigged.
    """

    vector_id = "BEN-02"
    prevalence = 55.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=False)
        r["threeds_indicator"] = ctx.rng.choice(["frictionless", "authenticated", "none"])
        r["cvv_result"] = "M"
        r["avs_result"] = "Y"

        # travel: ~5% of legitimate ecom comes from non-home geographies
        if ctx.rng.random() < 0.05:
            r["source_geo_country"] = ctx.rng.choice(["GB", "DE", "FR", "JP", "CA", "MX", "BR"])
            r["source_geo_lat"] = round(ctx.rng.uniform(-40, 65), 4)
            r["source_geo_lon"] = round(ctx.rng.uniform(-130, 140), 4)
            r["rtt_ms"] = ctx.rng.randint(60, 300)

        # AVS mismatch: ~8% of real transactions fail AVS for innocuous reasons
        if ctx.rng.random() < 0.08:
            r["avs_result"] = ctx.rng.choice(["N", "U", "S"])

        # CVV: rare but real, ~2% mistype
        if ctx.rng.random() < 0.02:
            r["cvv_result"] = ctx.rng.choice(["N", "P"])

        # new device: ~4% logged in from a new browser or phone
        if ctx.rng.random() < 0.04:
            r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"

        if ctx.rng.random() < 0.06:  # ordinary novelty: new merchant, still legitimate
            r["merchant_id"] = _novel_merchant(ctx.rng)
        if ctx.rng.random() < 0.03:  # ordinary decline
            r["approved"] = False
            r["response_code"] = "51"
            r["decline_reason"] = "insufficient_funds"
        return [r]


@register
class BenignRecurring(BenignGenerator):
    """BEN-03. Established subscription series, including legitimate price rises.

    Exists so that MND-07 style change-point features cannot win for free.
    """

    vector_id = "BEN-03"
    prevalence = 10.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        base = int(ctx.rng.lognormvariate(7.5, 0.5))
        seq = ctx.rng.randint(2, 40)
        r = base_record(ctx, agentic=False)
        r["series_id"] = f"ser_{ctx.rng.getrandbits(32):08x}"
        r["series_sequence"] = seq
        r["series_baseline_amount_minor"] = base
        r["series_interval_days"] = ctx.rng.choice([7.0, 30.0, 90.0, 365.0])
        r["series_beneficiary_id"] = f"ben_{ctx.rng.getrandbits(24):06x}"
        uplift = ctx.rng.choice([1.0, 1.0, 1.0, 1.05, 1.12])  # genuine price increases happen
        r["amount_minor"] = int(base * uplift)
        r["mcc"] = "5968"
        return [r]


# ---------------------------------------------------------------------------
# W2: NEW GENERATORS — TIER 1 & 2
# ---------------------------------------------------------------------------


@register
class IncrementalScopeCreep(Generator):
    """MND-03. Incremental authorization walks captured amount upward in steps.

    Each increment sits inside per-transaction tolerance, but the cumulative
    capture ends far above original consent. On v_network this looks like a
    series of small follow-on auths on an established relationship.
    """

    vector_id = "MND-03"
    prevalence = 2.0
    expected_records = 4.0

    def constraints(self, g: dict[str, Any]) -> bool:
        # Reject jointly implausible: too many increments with too large a ratio
        # would exceed the overage ratio in fewer steps than declared
        return not (g["increment_count"] > 15 and g["per_increment_ratio"] > 1.2)

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        n = int(g["increment_count"])
        base_r = base_record(ctx, agentic=True)
        original_amount = base_r["amount_minor"]
        base_r["consent_amount_minor"] = original_amount
        base_r["auth_type"] = "initial"
        base_r["cumulative_captured_minor"] = original_amount
        base_r["mcc"] = {"travel": "4722", "hospitality": "7011", "fuel": "5542",
                         "marketplace": "5999", "services": "7299"}[g["merchant_category"]]
        out = [mark_fraud(base_r, 0, False)]  # initial is clean

        running = original_amount
        for i in range(1, n):
            ts = ctx.now + timedelta(hours=i * ctx.rng.uniform(0.5, 6.0))
            r = base_record(ctx, agentic=True, ts=ts)
            r["auth_type"] = "incremental"
            r["original_txn_id"] = base_r["txn_id"]
            increment = int(running * (g["per_increment_ratio"] - 1.0))
            running += increment
            r["amount_minor"] = increment
            r["consent_amount_minor"] = original_amount
            r["cumulative_captured_minor"] = running
            r["mcc"] = base_r["mcc"]
            r["merchant_id"] = base_r["merchant_id"]
            r["merchant_descriptor"] = base_r["merchant_descriptor"]
            # stop if overage target reached
            if running > original_amount * g["total_overage_ratio"]:
                loss = running - original_amount
                out.append(mark_fraud(r, loss))
                break
            out.append(mark_fraud(r, running - original_amount))
        return out


@register
class SubCapStructuring(Generator):
    """MND-04. Splits spend into many txns each just under the per-txn cap.

    On v_network each record is unremarkable; the signal is the cluster of
    amounts immediately below a policy threshold across sessions or merchants.
    """

    vector_id = "MND-04"
    prevalence = 2.5
    expected_records = 8.0
    MAX_EMIT = 60

    def constraints(self, g: dict[str, Any]) -> bool:
        return g["split_count"] >= 3

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        n = min(int(g["split_count"]), self.MAX_EMIT)
        cap = ctx.actor.mandate_per_txn_cap_minor
        proximity = g["cap_proximity"]
        merchants_used = min(int(g["merchant_spread"]), 15)
        merchant_pool = [_novel_merchant(ctx.rng) for _ in range(merchants_used)]
        window_s = g["window_hours"] * 3600

        out = []
        for i in range(n):
            ts = ctx.now + timedelta(seconds=window_s * i / max(n, 1))
            r = base_record(ctx, agentic=True, ts=ts)
            r["amount_minor"] = int(cap * proximity * ctx.rng.uniform(0.95, 1.0))
            r["consent_amount_minor"] = r["amount_minor"]
            r["merchant_id"] = ctx.rng.choice(merchant_pool)
            r["mandate_per_txn_cap_minor"] = cap
            r["user_confirmation_events"] = 1
            out.append(mark_fraud(r, r["amount_minor"]))
        return out


@register
class ReviewCorpusInjection(Generator):
    """AGH-02. Review text seeds redirect purchase to attacker listing.

    On v_network this is a purchase at a below-median price from a new seller.
    The review burst and seller youth are merchant-side signals, stranded
    unless attested.
    """

    vector_id = "AGH-02"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["merchant_tenure_days"] = int(g["seller_account_age_days"])
        r["merchant_descriptor"] = "MARKETPLACE SELLER"
        # price below category median
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * g["price_ratio_to_median"])
        r["consent_amount_minor"] = r["amount_minor"]
        r["advertised_amount_minor"] = r["amount_minor"]
        # review recency signal
        r["merchant_dispute_rate_bps"] = 0  # new seller, no disputes yet
        r["user_confirmation_events"] = 1
        r["user_interaction_events"] = ctx.rng.randint(3, 10)
        return [mark_fraud(r, r["amount_minor"])]


@register
class HiddenDOMInjection(Generator):
    """AGH-03. Instructions in meta tags, JSON-LD, or zero-opacity nodes.

    On v_network, this is an approved agentic auth from a known merchant. The
    mismatch between rendered visible text and extracted agent context is the
    tell, and only the agent platform can attest it.
    """

    vector_id = "AGH-03"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        # visible vs extracted text mismatch
        r["page_visible_text_hash"] = f"v{ctx.rng.getrandbits(48):012x}"
        r["page_extracted_text_hash"] = f"x{ctx.rng.getrandbits(48):012x}"
        r["injection_classifier_score"] = round(
            min(0.99, 0.3 + 0.5 * g["obfuscation_level"]), 4)
        if g["endpoint_mismatch"]:
            r["payee_mutation_source"] = "web_page"
            r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
            r["merchant_id"] = _novel_merchant(ctx.rng)
        r["user_confirmation_events"] = 0 if ctx.rng.random() < 0.5 else 1
        r["cart_build_to_submit_ms"] = ctx.rng.randint(100, 2000)
        return [mark_fraud(r, r["amount_minor"])]


@register
class SEOPoisoning(Generator):
    """AGH-04. Agent navigates to a keyword-heavy injected landing page.

    On v_network, the domain age and acquisition channel (organic search) are
    the tells. MCC may not match the stated query intent.
    """

    vector_id = "AGH-04"
    prevalence = 1.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["amount_minor"] = int(g["requested_amount_usd"] * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["merchant_descriptor"] = "DIGITAL SERVICE"
        r["merchant_domain"] = f"svc-{ctx.rng.getrandbits(24):06x}.com"
        r["merchant_domain_first_seen"] = (
            ctx.now - timedelta(days=int(g["domain_age_days"]))).isoformat(timespec="milliseconds")
        r["merchant_tenure_days"] = int(g["domain_age_days"])
        r["acquisition_channel"] = "organic_search"
        # MCC depends on query intent
        mcc_map = {"software_dependency": "5734", "api_key": "7372",
                   "subscription": "5968", "service_fee": "7299", "physical_goods": "5999"}
        r["mcc"] = mcc_map.get(g["query_intent"], "5999")
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"])]


@register
class EmailInjection(Generator):
    """AGH-07. Transactional email contains instructions the agent processes.

    On v_network this looks like a normal payment. The payee change provenance
    originating from an inbound message is an agent-platform signal.
    """

    vector_id = "AGH-07"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["payee_mutation_source"] = "email"
        r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
        r["user_event_within_mutation_window"] = False
        r["memory_write_to_use_latency_hours"] = round(ctx.rng.uniform(0.1, 48.0), 2)
        if g["instruction_type"] == "amount_change":
            r["amount_minor"] = int(r["amount_minor"] * ctx.rng.uniform(1.5, 4.0))
        elif g["instruction_type"] == "urgency_payment":
            r["amount_minor"] = int(ctx.rng.uniform(500, 5000) * USD)
        elif g["instruction_type"] == "refund_redirect":
            r["amount_minor"] = int(ctx.rng.uniform(100, 2000) * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        if g["thread_hijack"]:
            r["merchant_descriptor"] = "KNOWN VENDOR"
            r["merchant_id"] = ctx.rng.choice(ctx.actor.known_merchants) if ctx.actor.known_merchants else "mid_000001"
        else:
            r["merchant_id"] = _novel_merchant(ctx.rng)
        r["user_confirmation_events"] = 0
        return [mark_fraud(r, r["amount_minor"])]


@register
class AgentImpersonation(Generator):
    """IDS-01. Attacker traffic declares itself as a well-known agent.

    On v_network the declared identity is present but attestation is absent or
    failed. Merchants relaxing controls for known agents are exploited.
    """

    vector_id = "IDS-01"
    prevalence = 3.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        # the lie: declared identity without attestation
        agent_map = {"major_assistant": "prov_openai", "browser_agent": "prov_browser",
                     "shopping_agent": "prov_shopbot", "crawler": "prov_crawler"}
        r["declared_agent_identity"] = agent_map.get(g["impersonated_agent"], "prov_unknown")
        r["agent_attestation_status"] = "absent" if not g["attestation_present"] else "verified"
        r["agent_attestation_method"] = "none" if not g["attestation_present"] else "http_message_signature"
        if not g["asn_consistency"]:
            r["source_ip_asn"] = ctx.rng.randint(60000, 65000)
        r["user_confirmation_events"] = 1
        r["amount_minor"] = int(ctx.rng.uniform(20, 500) * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        return [mark_fraud(r, r["amount_minor"])]


@register
class CounterfeitStorefront(Generator):
    """IDS-03. Fraudulent storefront engineered for agent heuristics.

    Perfect structured signals (schema, reviews, SSL) but very young site
    with below-market pricing. Agent optimising for best price gets caught.
    """

    vector_id = "IDS-03"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["merchant_descriptor"] = "PREMIUM ELECTRONICS"
        r["merchant_tenure_days"] = int(g["site_age_days"])
        r["merchant_domain"] = f"shop-{ctx.rng.getrandbits(24):06x}.store"
        r["merchant_domain_first_seen"] = (
            ctx.now - timedelta(days=int(g["site_age_days"]))).isoformat(timespec="milliseconds")
        # below market pricing
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * g["price_ratio_to_market"])
        r["consent_amount_minor"] = r["amount_minor"]
        r["advertised_amount_minor"] = r["amount_minor"]
        r["merchant_dispute_rate_bps"] = 0  # no history
        r["acquisition_channel"] = "organic_search"
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"])]


@register
class StoredValueDrain(Generator):
    """XRL-03. Agent purchases gift cards and discloses the codes.

    On v_network the MCC (stored value) is inconsistent with the task intent.
    The code disclosure event is agent-platform-only.
    """

    vector_id = "XRL-03"
    prevalence = 1.5
    expected_records = 3.0
    MAX_EMIT = 30

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        n = min(int(g["instrument_count"]), self.MAX_EMIT)
        out = []
        for i in range(n):
            ts = ctx.now + timedelta(minutes=i * ctx.rng.uniform(1, 10))
            r = base_record(ctx, agentic=True, ts=ts)
            r["amount_minor"] = int(g["face_value_usd"] * USD)
            r["consent_amount_minor"] = r["amount_minor"]
            r["mcc"] = "6540"  # stored value / gift cards
            r["merchant_descriptor"] = "GIFT CARD PURCHASE"
            r["merchant_id"] = _novel_merchant(ctx.rng)
            r["user_confirmation_events"] = 1 if g["task_mcc_consistency"] else 0
            out.append(mark_fraud(r, r["amount_minor"]))
        return out


@register
class InvoiceRedirection(Generator):
    """XRL-04. Supplier banking details changed on a genuine payable.

    On v_network, this is a payment to a known supplier at a plausible amount.
    The bank detail change originated out-of-channel (agent memory or email)
    is the stranded signal.
    """

    vector_id = "XRL-04"
    prevalence = 1.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["amount_minor"] = int(g["invoice_value_usd"] * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        r["mcc"] = "4829"  # B2B / wire
        r["merchant_descriptor"] = "SUPPLIER INVOICE"
        r["merchant_tenure_days"] = int(g["supplier_relationship_months"] * 30)
        if g["channel_deviation"]:
            r["payee_mutation_source"] = "email"
            r["user_event_within_mutation_window"] = False
        else:
            r["payee_mutation_source"] = "user_utterance"
            r["user_event_within_mutation_window"] = True
        r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
        r["memory_write_to_use_latency_hours"] = round(ctx.rng.uniform(1, 168), 2)
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"])]


# ---------------------------------------------------------------------------
# W2: NEW GENERATORS — TIER 3
# ---------------------------------------------------------------------------


@register
class RecurringMandateHijack(Generator):
    """MND-07. A legitimate recurring mandate is modified in amount or beneficiary.

    On v_network the series_id is established and the credential is trusted.
    The step change in amount or the beneficiary swap is the signal.
    """

    vector_id = "MND-07"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        base_amount = int(ctx.rng.lognormvariate(7.5, 0.5))
        r["series_id"] = f"ser_{ctx.rng.getrandbits(32):08x}"
        r["series_sequence"] = int(g["series_age_months"] * ctx.rng.uniform(1, 4))
        r["series_baseline_amount_minor"] = base_amount
        r["series_interval_days"] = ctx.rng.choice([7.0, 30.0, 90.0])
        r["amount_minor"] = int(base_amount * g["amount_step_ratio"])
        r["consent_amount_minor"] = r["amount_minor"]
        r["mcc"] = "5968"
        if g["beneficiary_changed"]:
            r["series_beneficiary_id"] = f"ben_new_{ctx.rng.getrandbits(24):06x}"
            r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
            r["payee_mutation_source"] = "email"
            r["user_event_within_mutation_window"] = False
        else:
            r["series_beneficiary_id"] = f"ben_{ctx.rng.getrandbits(24):06x}"
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"] - base_amount)]


@register
class CredentialTheftReplay(Generator):
    """IDS-02. Stolen agent attestation credential replayed from foreign infra.

    Passes Know Your Agent checks. Signal is concurrent origins or behavioural
    divergence from the credential's history, both issuer/agent-platform side.
    """

    vector_id = "IDS-02"
    prevalence = 1.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["agent_attestation_status"] = "verified"
        r["agent_credential_id"] = f"cred_{ctx.rng.getrandbits(32):08x}"
        r["agent_credential_issued_at"] = (
            ctx.now - timedelta(days=int(g["credential_age_days"]))).isoformat(timespec="milliseconds")
        # behavioural divergence: different geo, timing
        if g["behavioural_divergence"] > 0.5:
            r["source_geo_country"] = ctx.rng.choice(["RO", "NG", "VN"])
            r["source_geo_lat"] = round(ctx.rng.uniform(-30, 60), 4)
            r["source_geo_lon"] = round(ctx.rng.uniform(-60, 130), 4)
            r["rtt_ms"] = ctx.rng.randint(150, 500)
        r["user_confirmation_events"] = 0
        r["user_interaction_events"] = ctx.rng.randint(0, 2)
        return [mark_fraud(r, r["amount_minor"])]


@register
class StructuredDataPriceBait(Generator):
    """IDS-04. Feed price differs from auth amount: agent compares feeds not pages.

    On v_network the auth amount is legitimate-looking. The discrepancy between
    advertised and authorized is merchant-side, stranded unless attested.
    """

    vector_id = "IDS-04"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        advertised = r["amount_minor"]
        r["advertised_amount_minor"] = advertised
        r["amount_minor"] = int(advertised * g["auth_to_feed_price_ratio"])
        r["consent_amount_minor"] = r["amount_minor"]
        if g["currency_switch"]:
            r["settlement_currency"] = ctx.rng.choice(["GBP", "EUR", "JPY"])
            r["settlement_amount_minor"] = int(r["amount_minor"] * ctx.rng.uniform(0.7, 1.5))
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"] - advertised)]


@register
class CollusionRing(Generator):
    """IDS-07. Buyer and merchant agents controlled by same actor transact mutually.

    Each individual txn is unremarkable. The signal is graph structure:
    abnormal reciprocity and templated fulfilment. Fan-out capped explicitly.
    """

    vector_id = "IDS-07"
    prevalence = 1.5
    expected_records = 6.0
    MAX_EMIT = 30

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        pairs = min(int(g["txn_per_pair"]) * min(int(g["ring_size"]), 10), self.MAX_EMIT)
        out = []
        ring_merchants = [_novel_merchant(ctx.rng) for _ in range(min(int(g["ring_size"]), 10))]
        for i in range(pairs):
            ts = ctx.now + timedelta(minutes=i * ctx.rng.uniform(5, 60))
            r = base_record(ctx, agentic=True, ts=ts)
            r["merchant_id"] = ctx.rng.choice(ring_merchants)
            r["amount_minor"] = int(ctx.rng.uniform(20, 300) * USD)
            r["consent_amount_minor"] = r["amount_minor"]
            r["user_confirmation_events"] = 1
            r["merchant_tenure_days"] = ctx.rng.randint(10, 200)
            out.append(mark_fraud(r, r["amount_minor"]))
        return out


@register
class CallCentreSocialEngineering(Generator):
    """CGA-08. Scripted social engineering of issuer staff for credential reissue.

    Control vector. A servicing action (reissue, limit increase) is followed
    rapidly by high-value spend. KBA passed with atypical answer latency.
    """

    vector_id = "CGA-08"
    prevalence = 2.0
    expected_records = 2.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        out = []
        # servicing event, then spend
        spend_ts = ctx.now + timedelta(minutes=g["time_to_spend_minutes"])
        r = base_record(ctx, agentic=False, ts=spend_ts)
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * ctx.rng.uniform(3.0, 15.0))
        r["stepup_performed"] = True
        r["stepup_method"] = ctx.rng.choice(["otp_sms", "kba", "voice_biometric"])
        r["stepup_response_latency_ms"] = ctx.rng.randint(80, 800)
        # sophisticated: may not trip obvious geo tells
        if g["kba_pass_confidence"] > 0.8:
            r["device_fingerprint_id"] = ctx.actor.device_fingerprint_id
        else:
            r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"
        r["cvv_result"] = "M"
        r["avs_result"] = ctx.rng.choice(["Y", "N"])
        out.append(mark_fraud(r, r["amount_minor"]))
        # often a second purchase follows
        if ctx.rng.random() < 0.6:
            ts2 = spend_ts + timedelta(minutes=ctx.rng.uniform(5, 60))
            r2 = base_record(ctx, agentic=False, ts=ts2)
            r2["merchant_id"] = _novel_merchant(ctx.rng)
            r2["amount_minor"] = int(r["amount_minor"] * ctx.rng.uniform(0.3, 0.8))
            r2["cvv_result"] = "M"
            out.append(mark_fraud(r2, r2["amount_minor"]))
        return out


@register
class VoiceCloneStepup(Generator):
    """CGA-01. Voice clone defeats step-up authentication challenge.

    Control vector. Step-up is passed with atypical response latency. The
    audio artefact score is agent-platform/issuer side, not on the wire.
    """

    vector_id = "CGA-01"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=False)
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * ctx.rng.uniform(2.0, 8.0))
        r["stepup_performed"] = True
        challenge_map = {"voice_biometric": "voice_biometric",
                         "call_centre": "kba", "ivr_passphrase": "otp_sms"}
        r["stepup_method"] = challenge_map.get(g["challenge_type"], "voice_biometric")
        r["stepup_response_latency_ms"] = int(g["response_latency_ms"])
        r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"
        r["source_geo_country"] = ctx.rng.choice(["US", "GB", "CA"])
        r["cvv_result"] = "M"
        r["avs_result"] = ctx.rng.choice(["Y", "N"])
        return [mark_fraud(r, r["amount_minor"])]


@register
class SyntheticIdentity(Generator):
    """CGA-05. Fabricated identity aged through small activity then bust out.

    Control vector. Thin file with clean early behaviour, then sudden high
    spend. Shared attributes across cohort are the tell.
    """

    vector_id = "CGA-05"
    prevalence = 2.0
    expected_records = 2.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        out = []
        r = base_record(ctx, agentic=False)
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * g["bustout_multiple"])
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"
        r["device_first_seen"] = (
            ctx.now - timedelta(days=int(g["aging_months"] * 30))).isoformat(timespec="milliseconds")
        r["cvv_result"] = "M"
        r["avs_result"] = "Y"
        out.append(mark_fraud(r, r["amount_minor"]))
        # second high-value purchase
        if ctx.rng.random() < 0.5:
            ts2 = ctx.now + timedelta(hours=ctx.rng.uniform(1, 12))
            r2 = base_record(ctx, agentic=False, ts=ts2)
            r2["amount_minor"] = int(r["amount_minor"] * ctx.rng.uniform(0.5, 1.2))
            r2["merchant_id"] = _novel_merchant(ctx.rng)
            r2["device_fingerprint_id"] = r["device_fingerprint_id"]
            r2["cvv_result"] = "M"
            out.append(mark_fraud(r2, r2["amount_minor"]))
        return out


@register
class RefundAbuse(Generator):
    """XRL-01. Fabricated non-delivery claims with policy-tuned narratives.

    Deferred from full settlement model: simulated as the original purchase
    that will be disputed. The claim rate per account is the signal.
    """

    vector_id = "XRL-01"
    prevalence = 1.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=True)
        r["amount_minor"] = int(g["claim_value_usd"] * USD)
        r["consent_amount_minor"] = r["amount_minor"]
        r["mcc"] = "5999"
        r["merchant_descriptor"] = "ONLINE RETAIL"
        r["user_confirmation_events"] = 1
        return [mark_fraud(r, r["amount_minor"])]


@register
class MuleNetworkOrchestration(Generator):
    """XRL-06. Funds layered through many low-value accounts.

    Individual txns are small and unremarkable. The fan-in/fan-out graph
    motif and unnaturally short holding times are the signals.
    """

    vector_id = "XRL-06"
    prevalence = 1.5
    expected_records = 5.0
    MAX_EMIT = 30

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        layers = int(g["layers"])
        per_layer = min(int(g["accounts_per_layer"]), 10)
        n = min(layers * per_layer, self.MAX_EMIT)
        out = []
        for i in range(n):
            ts = ctx.now + timedelta(minutes=g["holding_time_minutes"] * i / max(n, 1))
            r = base_record(ctx, agentic=False, ts=ts)
            r["amount_minor"] = int(ctx.rng.uniform(50, 500) * USD)
            r["account_id"] = f"acct_mule_{ctx.rng.getrandbits(24):06x}"
            r["merchant_id"] = f"mid_mule_{ctx.rng.randint(1, 100):06d}"
            r["mcc"] = "6012"  # financial institution
            r["cvv_result"] = "M"
            r["avs_result"] = "Y"
            out.append(mark_fraud(r, r["amount_minor"]))
        return out


@register
class APPSocialEngineering(Generator):
    """CGA-04. Victim authorizes payment themselves under social pressure.

    Control vector. Every credential and behavioural signal is genuine. The
    fraud lives entirely in the intent layer, the closest classical analogue
    to agentic fraud.
    """

    vector_id = "CGA-04"
    prevalence = 2.0
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=False)
        # genuine credentials, genuine device, genuine location
        r["amount_minor"] = int(ctx.actor.typical_amount_minor *
                                g["amount_vs_balance_ratio"] * ctx.rng.uniform(5, 20))
        r["merchant_id"] = _novel_merchant(ctx.rng)
        r["merchant_descriptor"] = "INVESTMENT PLATFORM"
        r["mcc"] = "6211"  # securities
        r["payee_id"] = f"payee_{ctx.rng.getrandbits(32):08x}"
        r["cvv_result"] = "M"
        r["avs_result"] = "Y"
        r["threeds_indicator"] = "authenticated"
        # everything looks legitimate, which is the whole problem
        return [mark_fraud(r, r["amount_minor"])]


@register
class ConversationalOTPRelay(Generator):
    """CGA-09. Automated front end relays OTP from victim to attacker session.

    Control vector. OTP consumed from a different session than the one that
    requested it. Very tight timing between issuance and use.
    """

    vector_id = "CGA-09"
    prevalence = 2.5
    expected_records = 1.0

    def emit(self, ctx: Context, g: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        r = base_record(ctx, agentic=False)
        r["amount_minor"] = int(ctx.actor.typical_amount_minor * ctx.rng.uniform(1.5, 6.0))
        r["stepup_performed"] = True
        r["stepup_method"] = "otp_sms"
        r["stepup_response_latency_ms"] = int(g["relay_latency_seconds"] * 1000)
        # the key signal: OTP session mismatch
        r["otp_issued_session_id"] = f"sess_{ctx.rng.getrandbits(32):08x}"
        if g["session_mismatch"]:
            r["otp_consumed_session_id"] = f"sess_{ctx.rng.getrandbits(32):08x}"
        else:
            r["otp_consumed_session_id"] = r["otp_issued_session_id"]
        r["device_fingerprint_id"] = f"dev_{ctx.rng.getrandbits(40):010x}"
        r["cvv_result"] = "M"
        succeeded = ctx.rng.random() < g["success_rate"]
        r["approved"] = True  # auth succeeds when relay works
        return [mark_fraud(r, r["amount_minor"], succeeded)]

