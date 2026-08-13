from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from core.ingestor.parser import SharpHoundIngestor
from core.pathfinder.pathfinder import PathfinderCoordinator
from core.privesc.engine import PrivescEngine
from core.projects import ProjectManager
from core.remediation.engine import RemediationEngine
from utils.database import DatabaseManager

from .config import load_settings

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
MODEL_PATH = PROJECT_ROOT / "models" / "viper_rf_model.pkl"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class IngestRequest(BaseModel):
    zip_path: str = Field(..., min_length=1)
    project_id: str | None = None
    clear_database: bool = False


class SelectProjectRequest(BaseModel):
    project_id: str = Field(..., min_length=1)


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1)
    zip_path: str = Field("dev/20260702105422_VIPERTECH.zip", min_length=1)


class PathfindRequest(BaseModel):
    source_name: str = Field(..., min_length=1)
    target_name: str = Field(..., min_length=1)
    mode: Literal["tactical", "fasttrack", "predictive"] = "tactical"
    project_id: str | None = None


class PrivescPlanRequest(BaseModel):
    path: Any


class RemediationRequest(BaseModel):
    targets: list[dict[str, Any]] = Field(default_factory=list)


class TestDatabaseRequest(BaseModel):
    uri: str = Field("bolt://127.0.0.1:7687", min_length=1)
    username: str = Field("neo4j", min_length=1)
    password: str = Field(..., min_length=1)
    database: str = Field("neo4j", min_length=1)


class UserPreferencesRequest(BaseModel):
    theme_accent: str = Field("emerald")
    default_path_mode: str = Field("tactical")
    max_hops: int = Field(10, ge=1, le=50)
    ml_threshold: float = Field(0.70, ge=0.0, le=1.0)
    remediation_dir: str = Field("scripts")


def _db_manager(settings):
    manager = DatabaseManager(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    if not manager.connect():
        raise HTTPException(status_code=503, detail="Unable to connect to Neo4j.")
    return manager


def _resolve_project_path(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if PROJECT_ROOT not in candidate.parents and candidate != PROJECT_ROOT:
        raise HTTPException(status_code=400, detail="Path must stay within the ViperACL project directory.")

    return candidate


@lru_cache(maxsize=1)
def _load_predictive_model():
    if not MODEL_PATH.exists():
        return None
    return joblib.load(MODEL_PATH)


def _serialize_node(node):
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


def _path_to_sequence(path):
    if hasattr(path, "relationships"):
        sequence = []
        nodes = list(getattr(path, "nodes", []))
        relationships = list(getattr(path, "relationships", []))

        for index, relationship in enumerate(relationships):
            if index == 0 and nodes:
                sequence.append(_serialize_node(nodes[index]))
            sequence.append(getattr(relationship, "type", str(relationship)))
            if index + 1 < len(nodes):
                sequence.append(_serialize_node(nodes[index + 1]))
        return sequence

    if isinstance(path, list):
        sequence = []
        for index, item in enumerate(path):
            if index % 2 == 0:
                sequence.append(_serialize_node(item))
    props = dict(node)
    labels = list(getattr(node, "labels", []))
    return {
        "name": props.get("name") or props.get("objectid") or "UNKNOWN",
        "labels": labels,
        "objectid": props.get("objectid"),
    }


def _summarize_path(path_record, metrics=None, score=None):
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
            steps.append(
                {
                    "source": _serialize_node(source),
                    "relationship": rel_type,
                    "target": _serialize_node(target),
                }
            )
    else:
        nodes = getattr(path_record, "nodes", [])
        relationships = getattr(path_record, "relationships", [])
        sequence = []
        for index, rel in enumerate(relationships):
            source = nodes[index]
            target = nodes[index + 1]
            if index == 0:
                sequence.append(source)
            sequence.append(rel.type)
            sequence.append(target)
            steps.append(
                {
                    "source": _serialize_node(source),
                    "relationship": rel.type,
                    "target": _serialize_node(target),
                }
            )

    return {
        "step_count": len(steps),
        "steps": steps,
        "metrics": metrics or {},
        "score": score,
        "sequence": sequence,
    }


def _make_privesc_context():
    return SimpleNamespace(
        get_current_auth=lambda: {"username": "web@localhost", "value": ""},
        add_credential=lambda *args, **kwargs: None,
        switch_identity=lambda *args, **kwargs: True,
    )


def build_neo4j_snapshot(settings, project_id=None):
    manager = _db_manager(settings)
    try:
        if manager.connect():
            return manager.get_project_snapshot(project_id)
        return {
            "connected": False,
            "nodes": 0,
            "relationships": 0,
            "database": settings.neo4j_database,
            "uri": settings.neo4j_uri,
            "project_id": project_id,
        }
    finally:
        manager.close()


def _build_runtime_state(settings):
    project_mgr = ProjectManager()
    active_id = project_mgr.get_active_project_id()
    # Always fetch total overall database node & relationship count for landing page status
    snapshot = build_neo4j_snapshot(settings, project_id=None)

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


def create_app():
    settings = load_settings()
    app = FastAPI(title=settings.title, version=settings.version)
    app.state.settings = settings
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        runtime = _build_runtime_state(settings)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "settings": settings,
                "snapshot": runtime["snapshot"],
                "runtime": runtime,
            },
        )

    @app.get("/api/health")
    def health():
        runtime = _build_runtime_state(settings)
        snapshot = runtime["snapshot"]
        return {
            "status": "ok",
            "title": settings.title,
            "version": settings.version,
            "model_available": runtime["model_available"],
            "model_name": runtime["model_name"],
            "model_type": runtime["model_type"],
            "model_status_text": runtime["model_status_text"],
            "path_modes": runtime["path_modes"],
            "functions": runtime["functions"],
            "snapshot": snapshot,
            "active_project_id": runtime["active_project_id"],
            "active_project": runtime["active_project"],
            "projects": runtime["projects"],
            "neo4j_connected": snapshot["connected"],
            "neo4j_database": snapshot["database"],
            "neo4j_uri": snapshot["uri"],
        }

    @app.get("/api/projects")
    def list_projects():
        project_mgr = ProjectManager()
        return {
            "status": "ok",
            "active_project_id": project_mgr.get_active_project_id(),
            "projects": project_mgr.list_projects(),
        }

    @app.post("/api/projects/select")
    def select_project(request: SelectProjectRequest):
        project_mgr = ProjectManager()
        success = project_mgr.set_active_project(request.project_id)
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")

        runtime = _build_runtime_state(settings)
        return {
            "status": "ok",
            "active_project_id": request.project_id,
            "project": project_mgr.get_project(request.project_id),
            "snapshot": runtime["snapshot"],
        }

    @app.post("/api/projects/create")
    def create_project(request: CreateProjectRequest):
        project_mgr = ProjectManager()
        target_path = _resolve_project_path(request.zip_path)
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"Source zip file not found: {request.zip_path}")

        # Generate unique project_id
        timestamp_slug = Path(request.zip_path).stem
        project_id = f"proj_{timestamp_slug}"

        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            ingestor.ingest_zip(str(target_path))
            snapshot = manager.get_project_snapshot(project_id)
        finally:
            manager.close()

        nodes = snapshot.get("nodes", 0)
        rels = snapshot.get("relationships", 0)
        project_entry = project_mgr.register_project(
            project_id=project_id,
            name=request.name,
            source_zip=str(request.zip_path),
            nodes=nodes,
            relationships=rels,
        )

        return {
            "status": "ok",
            "project": project_entry,
            "snapshot": snapshot,
        }

    @app.delete("/api/projects/{project_id}")
    def delete_project(project_id: str):
        project_mgr = ProjectManager()
        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            ingestor.clear_database(project_id=project_id)
        finally:
            manager.close()

        success = project_mgr.delete_project(project_id)
        if not success:
            raise HTTPException(status_code=404, detail="Project not found in registry")

        runtime = _build_runtime_state(settings)
        return {
            "status": "ok",
            "deleted_project_id": project_id,
            "active_project_id": runtime["active_project_id"],
            "snapshot": runtime["snapshot"],
        }

    @app.post("/api/neo4j/test")
    def test_neo4j_connection(req: TestDatabaseRequest):
        test_mgr = DatabaseManager(
            uri=req.uri,
            username=req.username,
            password=req.password,
            database=req.database,
        )
        try:
            connected = test_mgr.connect()
            if connected:
                node_res = test_mgr.run_query("MATCH (n) RETURN count(n) AS node_count")
                nodes = node_res[0].get("node_count", 0) if node_res else 0
                return {
                    "status": "ok",
                    "connected": True,
                    "nodes": nodes,
                    "message": f"Connected to {req.uri}",
                    "details": f"Total Nodes: {nodes}",
                }
            return {
                "status": "error",
                "connected": False,
                "message": "Connection failed. Check URI or credentials.",
                "details": "",
            }
        except Exception as exc:
            return {"status": "error", "connected": False, "message": str(exc), "details": ""}
        finally:
            test_mgr.close()

    @app.post("/api/ingest")
    def ingest(request: IngestRequest):
        project_mgr = ProjectManager()
        project_id = request.project_id or project_mgr.get_active_project_id() or "proj_default"
        target_path = _resolve_project_path(request.zip_path)
        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            if request.clear_database:
                ingestor.clear_database(project_id=project_id)
            ingestor.ingest_zip(str(target_path), project_id=project_id)
            snapshot = manager.get_project_snapshot(project_id)
        finally:
            manager.close()

        project_mgr.update_project_stats(project_id, snapshot.get("nodes", 0), snapshot.get("relationships", 0))

        return {
            "status": "ok",
            "project_id": project_id,
            "zip_path": str(target_path),
            "cleared": request.clear_database,
            "snapshot": snapshot,
        }

    @app.post("/api/pathfind")
    def pathfind(request: PathfindRequest):
        manager = _db_manager(settings)
        try:
            coordinator = PathfinderCoordinator(manager)
            if request.mode == "predictive" and _load_predictive_model() is None:
                raise HTTPException(status_code=503, detail="Predictive model is not available.")

            results = coordinator.find_path(
                request.source_name,
                request.target_name,
                mode=request.mode,
                ml_model=_load_predictive_model() if request.mode == "predictive" else None,
            )
        finally:
            manager.close()

        extracted = []
        for record in results or []:
            path = record.get("p") or record.get("path")
            metrics = {
                key: value
                for key, value in record.items()
                if key in {"hops", "pathWeight", "success_probability"}
            }
            summary = _summarize_path(path, metrics=metrics, score=record.get("success_probability"))
            extracted.append(
                {
                    **summary,
                    "metrics": metrics,
                    "success_probability": record.get("success_probability"),
                    "pathWeight": record.get("pathWeight"),
                    "hops": record.get("hops"),
                }
            )

        return {
            "status": "ok",
            "mode": request.mode,
            "source_name": request.source_name.upper(),
            "target_name": request.target_name.upper(),
            "results": extracted,
            "result_count": len(extracted),
        }

    @app.post("/api/privesc/plan")
    def privesc_plan(request: PrivescPlanRequest):
        path = request.path
        if isinstance(path, dict):
            if "sequence" in path:
                path = path["sequence"]
            elif "steps" in path:
                sequence = []
                for step in path["steps"]:
                    sequence.append(step.get("source", {}))
                    sequence.append(step.get("relationship"))
                    sequence.append(step.get("target", {}))
                path = sequence

        if not path:
            raise HTTPException(status_code=400, detail="A path selection is required before building a privesc plan.")

        engine = PrivescEngine(None, settings.neo4j_database, settings.neo4j_uri, _make_privesc_context())
        try:
            engine.build_plan([{"p": path}])
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        tasks = []
        for rel, module in engine.task_queue:
            tasks.append(
                {
                    "type": rel.type,
                    "module": module.__class__.__name__,
                    "source": _serialize_node(getattr(rel, "start_node", None)),
                    "target": _serialize_node(getattr(rel, "end_node", None)),
                }
            )

        return {
            "status": "ok",
            "total_steps": len(tasks),
            "tasks": tasks,
        }

    @app.post("/api/remediation")
    def remediation(request: RemediationRequest):
        engine = RemediationEngine(output_dir=str(PROJECT_ROOT / "scripts"))
        success = engine.generate_script(request.targets)
        if not success:
            raise HTTPException(status_code=400, detail="No remediation script was generated.")

        return {
            "status": "ok",
            "generated": True,
            "output_path": engine.last_output_path,
            "target_count": len(request.targets),
        }

    return app