"""ReachPrioritizer FastAPI application."""
from __future__ import annotations

import logging
import os
import shutil
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_evaluation import router as evaluation_router
from app.api.routes_findings import router as findings_router
from app.api.routes_graph import router as graph_router
from app.api.routes_model import router as model_router
from app.api.routes_projects import router as projects_router
from app.api.routes_scans import router as scans_router
from app.api.routes_stats import router as stats_router
from app.config import ANALYZER_SCRIPT, CORS_ORIGINS, NODE_EXE
from app.models.database import initialize_db
from app.services.persistence import mark_interrupted_scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("reachprioritizer")
VERSION = "2.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_db()
    n = mark_interrupted_scans()
    if n:
        logger.warning("Marked %d interrupted scan(s) as failed", n)
    yield


app = FastAPI(
    title="ReachPrioritizer API",
    description="Reachability- and taint-aware, AI-assisted vulnerability prioritization for JavaScript / TypeScript / Node.js",
    version=VERSION,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

for r in (projects_router, scans_router, findings_router, graph_router, model_router, evaluation_router, stats_router):
    app.include_router(r)


@app.get("/")
@app.get("/health")
@app.get("/api/health")
def health():
    node = shutil.which(NODE_EXE) or (NODE_EXE if NODE_EXE and os.path.exists(NODE_EXE) else None)
    return {
        "status": "healthy" if node and ANALYZER_SCRIPT.exists() else "degraded",
        "service": "ReachPrioritizer API",
        "version": VERSION,
        "node": node,
        "analyzer": ANALYZER_SCRIPT.exists(),
    }
