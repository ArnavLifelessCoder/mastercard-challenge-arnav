"""
Agentic Red Team Simulator: record model, vantage projection, generator contract.

Three things live here and nothing else should:

  1. The auth record: construction, defaulting, and validation against
     schema/auth_record.yaml.
  2. Vantage projection: turning a whole record into the subset of fields a
     given experimental view is allowed to see. This is the experiment.
  3. The generator contract: what an attack generator or a benign generator has
     to implement, and how its sampled parameters are checked against the
     taxonomy so the two files cannot silently drift apart.

Design rule worth keeping: generators emit whole records carrying every vantage.
Projection happens once, at dataset build time, in one place. No generator ever
decides what a detector can see.
"""

from __future__ import annotations

import math
import random
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

import yaml

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"
GENERATOR_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSpec:
    name: str
    type: str
    vantage: str
    required: bool = False
    values: tuple[str, ...] | None = None
    attestable: bool = False
    group: str = ""


class Schema:
    """The auth record schema, loaded once and queried cheaply."""

    def __init__(self, doc: dict[str, Any]):
        self.meta = doc["meta"]
        self.vantages = doc["vantages"]
        self.views = doc["views"]
        self.fields: dict[str, FieldSpec] = {}
        for group, entries in doc["field_groups"].items():
            for e in entries:
                spec = FieldSpec(
                    name=e["name"],
                    type=e["type"],
                    vantage=e["vantage"],
                    required=bool(e.get("required", False)),
                    values=tuple(e["values"]) if e.get("values") else None,
                    attestable=bool(e.get("attestable", False)),
                    group=group,
                )
                if spec.name in self.fields:
                    raise ValueError(f"duplicate field in schema: {spec.name}")
                self.fields[spec.name] = spec

    @classmethod
    def load(cls, path: Path | None = None) -> "Schema":
        path = path or SCHEMA_DIR / "auth_record.yaml"
        return cls(yaml.safe_load(path.read_text()))

    def view_fields(self, view: str) -> list[str]:
        if view not in self.views:
            raise KeyError(f"unknown view {view!r}, have {sorted(self.views)}")
        cfg = self.views[view]
        vantages = set(cfg["include_vantages"])
        allow_attestable = bool(cfg.get("include_attestable", False))
        out = []
        for name, f in self.fields.items():
            if f.vantage == "ground_truth":
                continue
            if f.vantage in vantages or (allow_attestable and f.attestable):
                out.append(name)
        return out

    def ground_truth_fields(self) -> list[str]:
        return [n for n, f in self.fields.items() if f.vantage == "ground_truth"]


# ---------------------------------------------------------------------------
# Record validation
# ---------------------------------------------------------------------------

_PY_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "int": (int,),
    "float": (float, int),
    "bool": (bool,),
    "datetime": (datetime, str),
    "object": (dict,),
    "enum": (str,),
    "list[string]": (list,),
    "list[float]": (list,),
}


def validate_record(rec: dict[str, Any], schema: Schema) -> list[str]:
    """Return a list of problems. Empty list means the record is well formed."""
    problems: list[str] = []

    for name, value in rec.items():
        spec = schema.fields.get(name)
        if spec is None:
            problems.append(f"unknown field {name!r}")
            continue
        if value is None:
            if spec.required:
                problems.append(f"{name} is required but null")
            continue
        expected = _PY_TYPES.get(spec.type)
        if expected is None:
            problems.append(f"{name} has unmodelled type {spec.type!r}")
            continue
        # bool is a subclass of int in python, so check it first and explicitly
        if spec.type == "bool" and not isinstance(value, bool):
            problems.append(f"{name} expected bool, got {type(value).__name__}")
            continue
        if spec.type in ("int", "float") and isinstance(value, bool):
            problems.append(f"{name} expected {spec.type}, got bool")
            continue
        if not isinstance(value, expected):
            problems.append(f"{name} expected {spec.type}, got {type(value).__name__}")
            continue
        if spec.type == "float" and isinstance(value, float) and not math.isfinite(value):
            problems.append(f"{name} is not finite")
        if spec.values is not None and value not in spec.values:
            problems.append(f"{name} value {value!r} not in {list(spec.values)}")

    for name, spec in schema.fields.items():
        if spec.required and name not in rec:
            problems.append(f"{name} is required but missing")

    return problems


def project(rec: dict[str, Any], view: str, schema: Schema) -> dict[str, Any]:
    """Drop every field the view is not allowed to see. Ground truth always goes."""
    allowed = set(schema.view_fields(view))
    return {k: v for k, v in rec.items() if k in allowed}


def split_labels(rec: dict[str, Any], schema: Schema) -> dict[str, Any]:
    """Pull the ground truth block out of a record, for scoring."""
    gt = set(schema.ground_truth_fields())
    return {k: v for k, v in rec.items() if k in gt}


# ---------------------------------------------------------------------------
# Taxonomy binding and parameter sampling
# ---------------------------------------------------------------------------


class Taxonomy:
    def __init__(self, doc: dict[str, Any]):
        self.meta = doc["meta"]
        self.version = doc["meta"]["version"]
        self.vectors = {v["id"]: v for v in doc["vectors"]}
        self.families = doc["families"]
        self.rails = set(doc["rails_enum"])
        self.coverage = doc.get("coverage_summary", {})

    @classmethod
    def load(cls, path: Path | None = None) -> "Taxonomy":
        path = path or SCHEMA_DIR / "taxonomy.yaml"
        return cls(yaml.safe_load(path.read_text()))

    def params(self, vector_id: str) -> dict[str, dict[str, Any]]:
        return self.vectors[vector_id].get("parameters", {})

    def implemented(self) -> list[str]:
        return [k for k, v in self.vectors.items() if v.get("status") == "implemented"]


def sample_params(
    spec: dict[str, dict[str, Any]],
    rng: random.Random,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Draw one genome from a taxonomy parameter block.

    Marginal sampling only. Joint plausibility is the generator's job, expressed
    as a constraint function, because the taxonomy has no place to say that a
    200 day old storefront cannot also have a five year review history.
    """
    out: dict[str, Any] = {}
    for name, p in spec.items():
        t = p["type"]
        if t == "categorical":
            out[name] = rng.choice(p["values"])
        elif t == "bool":
            out[name] = rng.random() < 0.5
        elif t == "int":
            lo, hi = p["range"]
            out[name] = rng.randint(int(lo), int(hi))
        elif t == "float":
            lo, hi = p["range"]
            out[name] = rng.uniform(float(lo), float(hi))
        else:
            raise ValueError(f"unmodelled parameter type {t!r} for {name}")
    if overrides:
        out.update(overrides)
    return out


def check_params(
    values: dict[str, Any], spec: dict[str, dict[str, Any]], vector_id: str
) -> list[str]:
    """Catch generator drift from the taxonomy. Runs in tests, not in the hot loop."""
    problems = []
    missing = set(spec) - set(values)
    extra = set(values) - set(spec)
    if missing:
        problems.append(f"{vector_id}: genome missing {sorted(missing)}")
    if extra:
        problems.append(f"{vector_id}: genome has undeclared {sorted(extra)}")
    for name, p in spec.items():
        if name not in values:
            continue
        v = values[name]
        t = p["type"]
        if t == "categorical" and v not in p["values"]:
            problems.append(f"{vector_id}.{name}={v!r} not in {p['values']}")
        elif t == "bool" and not isinstance(v, bool):
            problems.append(f"{vector_id}.{name} expected bool")
        elif t in ("int", "float"):
            lo, hi = p["range"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                problems.append(f"{vector_id}.{name} expected {t}")
            elif not (lo <= v <= hi):
                problems.append(f"{vector_id}.{name}={v} outside [{lo}, {hi}]")
    return problems


# ---------------------------------------------------------------------------
# Generator contract
# ---------------------------------------------------------------------------


@dataclass
class Actor:
    """A cardholder and their standing agentic setup. Shared by benign and attack
    generators so an attack lands on a history rather than in a vacuum."""

    account_id: str
    issuer_country: str = "US"
    bin: str = "541234"
    device_fingerprint_id: str = ""
    device_first_seen: datetime | None = None
    agent_id: str = ""
    agent_provider_id: str = ""
    agent_provider_registered_at: datetime | None = None
    home_lat: float = 40.71
    home_lon: float = -74.01
    typical_amount_minor: int = 6500
    known_merchants: list[str] = dc_field(default_factory=list)
    mandate_per_txn_cap_minor: int = 50000
    mandate_window_cap_minor: int = 200000
    mandate_allowlist: list[str] = dc_field(default_factory=list)


@dataclass
class Context:
    """Everything a generator needs that is not its own genome."""

    now: datetime
    actor: Actor
    schema: Schema
    taxonomy: Taxonomy
    rng: random.Random


class Generator(ABC):
    """Base contract. One instance per vector, reused across episodes."""

    #: taxonomy id, or a benign id prefixed with BEN-
    vector_id: str = ""
    #: relative sampling weight when building a population, per episode
    prevalence: float = 1.0
    #: mean records this generator emits per episode. Used to convert episode
    #: weights into record weights. Without it, fan-out vectors like card
    #: testing silently dominate the dataset and the headline fraud rate lies.
    expected_records: float = 1.0
    #: how many rejection sampling attempts before giving up on constraints
    max_constraint_retries: int = 32

    def __init__(self, taxonomy: Taxonomy | None = None):
        self.taxonomy = taxonomy or Taxonomy.load()
        self._spec = self.taxonomy.params(self.vector_id) if self.is_attack else {}

    @property
    def is_attack(self) -> bool:
        return not self.vector_id.startswith("BEN-")

    @property
    def family(self) -> str:
        return self.taxonomy.vectors[self.vector_id]["family"] if self.is_attack else "benign"

    # -- overridable ------------------------------------------------------

    def constraints(self, genome: dict[str, Any]) -> bool:
        """Return False for a jointly implausible genome. Default accepts all.

        Override this rather than clamping inside emit, so that rejected regions
        stay visible to the coevolution loop instead of being silently folded
        onto a boundary.
        """
        return True

    def draw(self, rng: random.Random, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        for _ in range(self.max_constraint_retries):
            g = sample_params(self._spec, rng, overrides)
            if self.constraints(g):
                return g
        raise RuntimeError(
            f"{self.vector_id}: constraints rejected {self.max_constraint_retries} "
            "consecutive draws, the constraint is too tight for the declared ranges"
        )

    @abstractmethod
    def emit(self, ctx: Context, genome: dict[str, Any], campaign_id: str) -> list[dict[str, Any]]:
        """Produce one episode: one or more auth records sharing a campaign_id.

        Records must be whole. Populate agent_platform and merchant fields even
        though no deployable view will show them, because the omniscient ceiling
        and the stranded signal argument both depend on them existing.
        """

    # -- driver -----------------------------------------------------------

    def episode(self, ctx: Context, overrides: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        genome = self.draw(ctx.rng, overrides)
        campaign_id = uuid.UUID(int=ctx.rng.getrandbits(128)).hex[:16]
        records = self.emit(ctx, genome, campaign_id)
        for r in records:
            r.setdefault("label", "fraud" if self.is_attack else "benign")
            r.setdefault("vector_id", self.vector_id if self.is_attack else None)
            r.setdefault("family", self.family)
            r.setdefault("genome", genome if self.is_attack else {})
            r.setdefault("campaign_id", campaign_id)
            r["generator_version"] = GENERATOR_VERSION
            r["taxonomy_version"] = self.taxonomy.version
        return records


class BenignGenerator(Generator):
    """Marker base for the negative class. Same contract, label flipped.

    The negative class is not decoration. A detector evaluated only against
    attacks has no false positive story, and the decline rate claim in the
    headline experiment is unprovable without it.
    """

    prevalence: float = 100.0

    @property
    def is_attack(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Record helpers
# ---------------------------------------------------------------------------


def base_record(ctx: Context, *, agentic: bool, ts: datetime | None = None) -> dict[str, Any]:
    """A well formed, approved, unremarkable authorization. Generators mutate it.

    Starting every record from a clean approval matters: agentic fraud is
    supposed to look like a clean approval, so anything that fails to look
    clean is a bug in the generator, not a feature of the attack.
    """
    a = ctx.actor
    ts = ts or ctx.now
    rec: dict[str, Any] = {
        "txn_id": uuid.UUID(int=ctx.rng.getrandbits(128)).hex,
        "timestamp_utc": ts.astimezone(timezone.utc).isoformat(timespec="milliseconds"),
        "message_type": "auth_request",
        "auth_type": "initial",
        "processing_code": "000000",
        "amount_minor": max(100, int(ctx.rng.gauss(a.typical_amount_minor, a.typical_amount_minor * 0.35))),
        "currency": "USD",
        "account_id": a.account_id,
        "token_id": f"tok_{a.account_id[-6:]}",
        "token_type": "agentic_token" if agentic else "network_token",
        "token_assurance_level": "agent_binding" if agentic else "device_binding",
        "issuer_country": a.issuer_country,
        "bin": a.bin,
        "merchant_id": ctx.rng.choice(a.known_merchants) if a.known_merchants else "mid_000001",
        "merchant_descriptor": "KNOWN MERCHANT",
        "mcc": "5999",
        "acquirer_bin": "400001",
        "merchant_country": "US",
        "merchant_tenure_days": ctx.rng.randint(400, 4000),
        "channel": "ecom_agentic" if agentic else "ecom_human",
        "pos_entry_mode": "812",
        "ecom_indicator": "07",
        "source_geo_country": "US",
        "source_geo_lat": a.home_lat,
        "source_geo_lon": a.home_lon,
        "rtt_ms": ctx.rng.randint(8, 45),
        "device_fingerprint_id": a.device_fingerprint_id,
        "agent_present": agentic,
        "agent_attestation_status": "verified" if agentic else "absent",
        "response_code": "00",
        "approved": True,
        "attack_succeeded": False,
        "loss_minor": 0,
    }
    if agentic:
        rec.update(
            {
                "agent_id": a.agent_id,
                "agent_provider_id": a.agent_provider_id,
                "agent_attestation_method": "http_message_signature",
                "agent_type": "shopping",
                "declared_agent_identity": a.agent_provider_id,
                "delegation_depth": 1,
                "terminal_agent_id": a.agent_id,
                "terminal_agent_attested": True,
                "mandate_id": uuid.UUID(int=ctx.rng.getrandbits(128)).hex[:12],
                "mandate_type": "cart",
                "mandate_per_txn_cap_minor": a.mandate_per_txn_cap_minor,
                "mandate_window_cap_minor": a.mandate_window_cap_minor,
                "mandate_window_hours": 168.0,
                "mandate_allowlist_descriptors": list(a.mandate_allowlist),
                "mandate_use_count": 1,
                "consent_timestamp": (ts - timedelta(seconds=ctx.rng.randint(20, 400))).isoformat(timespec="milliseconds"),
                "consent_expiry": (ts + timedelta(hours=1)).isoformat(timespec="milliseconds"),
                "user_confirmation_events": 1,
                "user_interaction_events": ctx.rng.randint(3, 12),
                "session_id": uuid.UUID(int=ctx.rng.getrandbits(128)).hex[:12],
                "session_turn_index": ctx.rng.randint(1, 6),
                "session_objective_drift": round(ctx.rng.uniform(0.0, 0.08), 4),
                "cart_build_to_submit_ms": ctx.rng.randint(4000, 90000),
                "payee_mutation_source": "none",
                "declared_vs_executed_param_diff": 0.0,
                "tool_server_trust": "allowlisted",
            }
        )
        rec["consent_amount_minor"] = rec["amount_minor"]
        rec["mandate_hash"] = f"h{ctx.rng.getrandbits(48):012x}"
        rec["consent_recorded_hash"] = rec["mandate_hash"]
    return rec


def mark_fraud(rec: dict[str, Any], loss_minor: int, succeeded: bool = True) -> dict[str, Any]:
    rec["attack_succeeded"] = succeeded
    rec["loss_minor"] = int(loss_minor) if succeeded else 0
    return rec


# ---------------------------------------------------------------------------
# Registry and population builder
# ---------------------------------------------------------------------------


class Registry:
    def __init__(self):
        self._gens: dict[str, type[Generator]] = {}

    def register(self, cls: type[Generator]) -> type[Generator]:
        if not cls.vector_id:
            raise ValueError(f"{cls.__name__} has no vector_id")
        if cls.vector_id in self._gens:
            raise ValueError(f"duplicate generator for {cls.vector_id}")
        self._gens[cls.vector_id] = cls
        return cls

    def get(self, vector_id: str) -> type[Generator]:
        return self._gens[vector_id]

    def all(self) -> dict[str, type[Generator]]:
        return dict(self._gens)

    def attacks(self) -> dict[str, type[Generator]]:
        return {k: v for k, v in self._gens.items() if not k.startswith("BEN-")}

    def benign(self) -> dict[str, type[Generator]]:
        return {k: v for k, v in self._gens.items() if k.startswith("BEN-")}

    def coverage(self, taxonomy: Taxonomy) -> dict[str, list[str]]:
        want = set(taxonomy.implemented())
        have = set(self.attacks())
        return {
            "built": sorted(want & have),
            "declared_not_built": sorted(want - have),
            "built_not_declared": sorted(have - want),
        }


REGISTRY = Registry()


def register(cls: type[Generator]) -> type[Generator]:
    return REGISTRY.register(cls)


@dataclass
class PopulationConfig:
    n_episodes: int = 10_000
    fraud_rate: float = 0.012
    seed: int = 7
    start: datetime = dc_field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    days: int = 90
    n_actors: int = 500
    vectors: Sequence[str] | None = None  # None means every registered attack


def make_actor(rng: random.Random, i: int) -> Actor:
    merchants = [f"mid_{rng.randint(1, 400):06d}" for _ in range(rng.randint(3, 12))]
    return Actor(
        account_id=f"acct_{i:07d}",
        device_fingerprint_id=f"dev_{rng.getrandbits(40):010x}",
        agent_id=f"agent_{rng.getrandbits(32):08x}",
        agent_provider_id=rng.choice(["prov_alpha", "prov_bravo", "prov_charlie"]),
        home_lat=round(rng.uniform(25.0, 48.0), 4),
        home_lon=round(rng.uniform(-123.0, -70.0), 4),
        typical_amount_minor=int(rng.lognormvariate(8.6, 0.7)),
        known_merchants=merchants,
        mandate_per_txn_cap_minor=rng.choice([25000, 50000, 100000, 250000]),
        mandate_allowlist=[f"MERCHANT {m[-4:]}" for m in merchants[:4]],
    )


def build_population(
    cfg: PopulationConfig,
    registry: Registry = REGISTRY,
    schema: Schema | None = None,
    taxonomy: Taxonomy | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield whole records. Project them afterwards, once, per view."""
    schema = schema or Schema.load()
    taxonomy = taxonomy or Taxonomy.load()
    rng = random.Random(cfg.seed)

    actors = [make_actor(rng, i) for i in range(cfg.n_actors)]

    benign_cls = list(registry.benign().values())
    if not benign_cls:
        raise RuntimeError(
            "no benign generator registered: a dataset of attacks only has no "
            "false positive story and its AUC is meaningless"
        )
    attack_ids = list(cfg.vectors) if cfg.vectors else list(registry.attacks())
    if not attack_ids:
        raise RuntimeError("no attack generators registered")

    benign_inst = [c(taxonomy) for c in benign_cls]
    attack_inst = [registry.get(v)(taxonomy) for v in attack_ids]

    # Prevalence is declared per episode but fraud_rate is a record-level target,
    # which is what a payments person means by a fraud rate. Convert.
    def _mix(gens: list[Generator]) -> tuple[list[float], float]:
        w = [g.prevalence / max(g.expected_records, 1e-9) for g in gens]
        tot = sum(w) or 1.0
        mean_records = sum(wi * g.expected_records for wi, g in zip(w, gens)) / tot
        return w, mean_records

    benign_w, eb = _mix(benign_inst)
    attack_w, ef = _mix(attack_inst)
    t = cfg.fraud_rate
    p_episode = (t * eb) / (ef * (1 - t) + t * eb)

    for _ in range(cfg.n_episodes):
        is_fraud = rng.random() < p_episode
        pool, weights = (attack_inst, attack_w) if is_fraud else (benign_inst, benign_w)
        gen = rng.choices(pool, weights=weights, k=1)[0]
        ctx = Context(
            now=cfg.start + timedelta(seconds=rng.randint(0, cfg.days * 86400)),
            actor=rng.choice(actors),
            schema=schema,
            taxonomy=taxonomy,
            rng=rng,
        )
        yield from gen.episode(ctx)


def to_views(
    records: Iterable[dict[str, Any]], views: Sequence[str], schema: Schema
) -> dict[str, list[dict[str, Any]]]:
    """Materialise one dataset per view plus a shared label table.

    Split on campaign_id, never on txn_id. Episodes emit correlated records and
    a random row split leaks the attack across train and test.
    """
    out: dict[str, list[dict[str, Any]]] = {v: [] for v in views}
    out["_labels"] = []
    for r in records:
        for v in views:
            out[v].append(project(r, v, schema))
        out["_labels"].append(split_labels(r, schema))
    return out
