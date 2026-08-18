"""
ARTS Web Prototype: FastAPI serving the existing Python directly.

Endpoints:
  /api/taxonomy            list vectors, families, genome ranges
  /api/generate/{vid}      sample genome, generate episode, return records
  /api/detect              score a record through both views
  /api/results             serve headline.json
  /api/coevolution         serve coevolution.json (if exists)
  /                        serve the single-page frontend

Run: uvicorn web.app:app --reload --port 8000
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from arts import generators as _gen_module  # noqa: F401
from arts.core import (
    REGISTRY,
    Actor,
    Context,
    PopulationConfig,
    Schema,
    Taxonomy,
    build_population,
    project,
    sample_params,
    make_actor,
)
from arts.features import Featurizer
from experiments.headline import Arm, invariant_score, INVARIANTS, ALERT_RATE

app = FastAPI(title="ARTS Web Prototype", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

schema = Schema.load()
taxonomy = Taxonomy.load()
RESULTS_DIR = ROOT / "results"
WEB_DIR = Path(__file__).resolve().parent


# ---- pre-fit arm G for live scoring ----
_arm_g = None
_arm_a = None
_fz_network = None
_fz_attested = None


def _ensure_models():
    global _arm_g, _arm_a, _fz_network, _fz_attested
    if _arm_g is not None:
        return

    from experiments.headline import grouped_split

    rng = random.Random(17)
    records = list(build_population(
        PopulationConfig(n_episodes=10_000, fraud_rate=0.02, seed=17),
        schema=schema, taxonomy=taxonomy))

    train, calib, _ = grouped_split(records)

    _arm_a = Arm("A supervised v_network", "v_network", "supervised",
                 lambda r: r["label"] == "benign" or r.get("vector_id", "").startswith("CGA"))
    _arm_a.fit(train, calib, schema)

    _arm_g = Arm("G hybrid v_attested", "v_attested", "hybrid",
                 lambda r: r["label"] == "benign")
    _arm_g.fit(train, calib, schema)


# ---- API endpoints ----

@app.get("/")
async def index():
    return FileResponse(WEB_DIR / "index.html", media_type="text/html")


@app.get("/api/taxonomy")
async def get_taxonomy():
    vectors = []
    for vid, v in taxonomy.vectors.items():
        vectors.append({
            "id": vid,
            "name": v.get("name", ""),
            "family": v.get("family", ""),
            "mechanism": v.get("mechanism", ""),
            "signals": v.get("signals", []),
            "difficulty": v.get("difficulty", 0.5),
            "status": v.get("status", "stub"),
            "parameters": v.get("parameters", {}),
            "defense_hooks": v.get("defense_hooks", []),
            "rails": v.get("rails", []),
            "genai_leverage": v.get("genai_leverage", ""),
        })
    families = taxonomy.families
    coverage = REGISTRY.coverage(taxonomy)
    return {
        "vectors": vectors,
        "families": families,
        "coverage": coverage,
        "meta": taxonomy.meta,
    }


class GenerateRequest(BaseModel):
    vector_id: str
    seed: int | None = None


@app.post("/api/generate")
async def generate(req: GenerateRequest):
    vid = req.vector_id
    if vid not in REGISTRY.all():
        raise HTTPException(404, f"Unknown vector: {vid}")

    rng = random.Random(req.seed or random.randint(0, 2**32))
    gen = REGISTRY.get(vid)(taxonomy)
    actor = make_actor(rng, 0)
    ctx = Context(
        now=datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        actor=actor,
        schema=schema,
        taxonomy=taxonomy,
        rng=rng,
    )
    records = gen.episode(ctx)

    return {
        "vector_id": vid,
        "genome": records[0].get("genome", {}),
        "records": records,
        "record_count": len(records),
    }


class DetectRequest(BaseModel):
    records: list[dict[str, Any]]


@app.post("/api/detect")
async def detect(req: DetectRequest):
    _ensure_models()
    results = []
    for r in req.records:
        # project into both views
        r_net = project(r, "v_network", schema)
        r_att = project(r, "v_attested", schema)

        # score on both detectors
        score_a = float(_arm_a.score([r], schema)[0])
        score_g = float(_arm_g.score([r], schema)[0])
        flagged_a = score_a > _arm_a.thr
        flagged_g = score_g > _arm_g.thr

        # which invariants fired
        X_att = _arm_g.fz.transform([project(r, "v_attested", schema)])
        inv_scores = invariant_score(X_att, _arm_g.fz.names)
        fired_invariants = []
        idx = {n: i for i, n in enumerate(_arm_g.fz.names)}
        for name, _, thr in INVARIANTS:
            j = idx.get(name)
            if j is not None and X_att[0, j] > thr:
                fired_invariants.append(name)

        results.append({
            "v_network_fields": len(r_net),
            "v_attested_fields": len(r_att),
            "v_network_record": r_net,
            "v_attested_record": r_att,
            "arm_a_score": round(score_a, 6),
            "arm_a_flagged": bool(flagged_a),
            "arm_g_score": round(score_g, 6),
            "arm_g_flagged": bool(flagged_g),
            "invariants_fired": fired_invariants,
            "invariant_count": int(inv_scores[0]),
        })
    return {"results": results}


@app.get("/api/results")
async def get_results():
    path = RESULTS_DIR / "headline.json"
    if not path.exists():
        raise HTTPException(404, "headline.json not found. Run experiments/headline.py first.")
    return json.loads(path.read_text())


@app.get("/api/coevolution")
async def get_coevolution():
    path = RESULTS_DIR / "coevolution.json"
    if not path.exists():
        raise HTTPException(404, "coevolution.json not found. Run experiments/coevolution.py first.")
    return json.loads(path.read_text())
