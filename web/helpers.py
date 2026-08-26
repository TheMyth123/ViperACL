"""Shared helpers for ViperACL web routes."""

from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import joblib
from fastapi import HTTPException

from core.database import DatabaseManager
from core.projects import ProjectManager


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
RF_MODEL_PATH = PROJECT_ROOT / "models" / "rf_viper_model.pkl"
LEGACY_RF_MODEL_PATH = PROJECT_ROOT / "models" / "viper_rf_model.pkl"
LGBM_MODEL_PATH = PROJECT_ROOT / "models" / "lgbm_viper_model.pkl"
LGBM_SHAP_PATH = PROJECT_ROOT / "models" / "lgbm_shap_explainer.pkl"
TRANSFORMER_MODEL_PATH = PROJECT_ROOT / "models" / "transformer_viper_model.pt"
MODEL_PATH = RF_MODEL_PATH if RF_MODEL_PATH.exists() else LEGACY_RF_MODEL_PATH


def db_manager(settings, required=True):
    """Create and connect a DatabaseManager, raising HTTP 503 on failure if required."""
    manager = DatabaseManager(
        uri=getattr(settings, "neo4j_uri", "bolt://127.0.0.1:7687"),
        username=getattr(settings, "neo4j_username", "neo4j"),
        password=getattr(settings, "neo4j_password", "viperacl"),
        database=getattr(settings, "neo4j_database", "neo4j"),
    )
    if required and not manager.connect():
        raise HTTPException(status_code=503, detail="Unable to connect to Neo4j database.")
    return manager


def resolve_project_path(raw_path: str) -> Path:
    """Resolve and validate a path stays within the project directory."""
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
        raise HTTPException(status_code=400, detail="Path must stay within the ViperACL project directory.")

    return candidate


@lru_cache(maxsize=1)
def load_rf_model():
    """Load Random Forest ML model from disk (cached)."""
    target_path = RF_MODEL_PATH if RF_MODEL_PATH.exists() else LEGACY_RF_MODEL_PATH
    if not target_path.exists():
        return None
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        return joblib.load(target_path)


@lru_cache(maxsize=1)
def load_lgbm_model():
    """Load LightGBM ML model and TreeSHAP explainer from disk (cached)."""
    if not LGBM_MODEL_PATH.exists():
        return None, None
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        model = joblib.load(LGBM_MODEL_PATH)
        explainer = joblib.load(LGBM_SHAP_PATH) if LGBM_SHAP_PATH.exists() else None
        return model, explainer


@lru_cache(maxsize=1)
def load_transformer_model():
    """Load Path-Transformer PyTorch model from disk (cached)."""
    if not TRANSFORMER_MODEL_PATH.exists():
        return None
    import torch
    from core.pathfinder.transformer_model import NODE_TYPE_VOCAB, REL_TYPE_VOCAB, PathTransformer
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PathTransformer(
        node_vocab_size=len(NODE_TYPE_VOCAB) + 5,
        rel_vocab_size=len(REL_TYPE_VOCAB) + 5,
        d_model=64,
        n_heads=4,
        num_layers=2,
        max_hops=25,
    ).to(device)
    model.load_state_dict(torch.load(TRANSFORMER_MODEL_PATH, map_location=device))
    model.eval()
    return model


# Legacy alias
load_predictive_model = load_rf_model


def serialize_node(node) -> dict:
    """Safely converts a Neo4j Node or dict into a JSON-serializable dictionary."""
    if node is None:
        return {}

    if isinstance(node, dict):
        return {key: value for key, value in node.items() if value is not None}

    serialized = {}
    for key in ("name", "distinguishedname", "objectid", "labels"):
        value = getattr(node, key, None)
        if value is not None:
            serialized[key] = value

    if not serialized and hasattr(node, "get"):
        for key in ("name", "distinguishedname", "objectid"):
            value = node.get(key)
            if value is not None:
                serialized[key] = value

    if not serialized:
        serialized["value"] = str(node)

    return serialized


def summarize_path(path_record, metrics=None, score=None) -> dict:
    """Summarize a Neo4j path or list-style path into a JSON-friendly structure."""
    if not path_record:
        return {"step_count": 0, "steps": [], "metrics": metrics or {}, "score": score, "sequence": []}

    steps = []
    sequence = []

    if isinstance(path_record, list):
        sequence = list(path_record)
        for index in range(0, len(sequence) - 2, 2):
            source = sequence[index]
            rel = sequence[index + 1]
            target = sequence[index + 2]
            rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
            steps.append({
                "source": serialize_node(source),
                "relationship": rel_type,
                "target": serialize_node(target),
            })
    else:
        nodes = getattr(path_record, "nodes", [])
        relationships = getattr(path_record, "relationships", [])
        for index, rel in enumerate(relationships):
            source = nodes[index]
            target = nodes[index + 1]
            if index == 0:
                sequence.append(source)
            sequence.append(rel.type)
            sequence.append(target)
            steps.append({
                "source": serialize_node(source),
                "relationship": rel.type,
                "target": serialize_node(target),
            })

    return {
        "step_count": len(steps),
        "steps": steps,
        "metrics": metrics or {},
        "score": score,
        "sequence": sequence,
    }


def make_privesc_context():
    """Create a stub privesc context for web-based plan building."""
    return SimpleNamespace(
        get_current_auth=lambda: {"username": "web@localhost", "value": ""},
        add_credential=lambda *args, **kwargs: None,
        switch_identity=lambda *args, **kwargs: True,
    )


def build_neo4j_snapshot(settings, project_id=None) -> dict:
    """Query Neo4j for node/relationship counts without raising unhandled exceptions."""
    try:
        manager = DatabaseManager(
            uri=getattr(settings, "neo4j_uri", "bolt://127.0.0.1:7687"),
            username=getattr(settings, "neo4j_username", "neo4j"),
            password=getattr(settings, "neo4j_password", "viperacl"),
            database=getattr(settings, "neo4j_database", "neo4j"),
        )
        if manager.connect():
            try:
                return manager.get_project_snapshot(project_id)
            finally:
                manager.close()
    except Exception:
        pass

    return {
        "connected": False,
        "nodes": 0,
        "relationships": 0,
        "database": getattr(settings, "neo4j_database", "neo4j"),
        "uri": getattr(settings, "neo4j_uri", "bolt://127.0.0.1:7687"),
        "project_id": project_id,
    }


def build_runtime_state(settings) -> dict:
    """Build the full runtime state dict used by page templates and health endpoint."""
    project_mgr = ProjectManager()
    active_id = project_mgr.get_active_project_id()
    snapshot = build_neo4j_snapshot(settings, project_id=active_id)

    if active_id and snapshot.get("connected"):
        project_mgr.update_project_stats(active_id, snapshot.get("nodes", 0), snapshot.get("relationships", 0))

    projects = project_mgr.list_projects()
    active_project = project_mgr.get_project(active_id) if active_id else None

    model_exists = MODEL_PATH.exists()
    return {
        "snapshot": snapshot,
        "active_project_id": active_id,
        "active_project": active_project,
        "projects": projects,
        "model_available": model_exists,
        "model_name": MODEL_PATH.name,
        "model_type": "Random Forest",
        "model_status_text": "Optimized & Ready" if model_exists else "Model Unavailable",
        "path_modes": ["tactical", "fasttrack", "predictive"],
        "functions": ["ingest", "pathfind", "privesc", "remediation"],
    }
