from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import asyncio
import joblib
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from core.ingestor.parser import SharpHoundIngestor
from core.pathfinder.pathfinder import PathfinderCoordinator
from core.privesc.engine import PrivescEngine
from core.projects import ProjectManager
from core.remediation.engine import RemediationEngine
from utils.database import DatabaseManager
from utils.logger import logger

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
    """Safely converts a Neo4j Node or dict into a standard JSON-serializable dictionary."""
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
        active_snapshot = build_neo4j_snapshot(settings, project_id=active_id)
        project_mgr.update_project_stats(active_id, active_snapshot.get("nodes", 0), active_snapshot.get("relationships", 0))

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

    # Log application startup
    logger.info(
        "SYSTEM", "system.startup",
        f"ViperACL v{settings.version} starting — Neo4j target: {settings.neo4j_uri}",
        source="web.app",
        details={"neo4j_uri": settings.neo4j_uri, "neo4j_database": settings.neo4j_database},
    )

    # -----------------------------------------------------------------------
    # Pages
    # -----------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        runtime = _build_runtime_state(settings)
        logger.debug(
            "SYSTEM", "system.dashboard.loaded",
            "Landing page loaded",
            source="web.app",
        )
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "active_page": "launchpad",
                "settings": settings,
                "snapshot": runtime["snapshot"],
                "runtime": runtime,
            },
        )

    @app.get("/logs", response_class=HTMLResponse)
    def logs_page(request: Request):
        runtime = _build_runtime_state(settings)
        logger.debug(
            "SYSTEM", "system.logs_page.loaded",
            "Global Logs page loaded",
            source="web.app",
        )
        return templates.TemplateResponse(
            request,
            "logs.html",
            {
                "active_page": "logs",
                "settings": settings,
                "snapshot": runtime["snapshot"],
                "runtime": runtime,
            },
        )

    # -----------------------------------------------------------------------
    # Logs API
    # -----------------------------------------------------------------------
    @app.get("/api/logs")
    def get_logs(
        limit: int = Query(200, ge=1, le=2000),
        offset: int = Query(0, ge=0),
        level: str | None = Query(None),
        category: str | None = Query(None),
        project_id: str | None = Query(None),
        search: str | None = Query(None),
        date_from: str | None = Query(None),
        date_to: str | None = Query(None),
    ):
        logs, total = logger.get_logs(
            limit=limit,
            offset=offset,
            level=level,
            category=category,
            project_id=project_id,
            search=search,
            date_from=date_from,
            date_to=date_to,
        )
        return {
            "status": "ok",
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/logs/stream")
    async def logs_stream():
        queue = logger.subscribe()

        async def event_generator():
            try:
                # Send an initial heartbeat
                yield "event: connected\ndata: {}\n\n"
                while True:
                    try:
                        entry = await asyncio.wait_for(queue.get(), timeout=30.0)
                        import json as _json
                        yield f"data: {_json.dumps(entry, default=str)}\n\n"
                    except asyncio.TimeoutError:
                        # Send keepalive comment to prevent connection timeout
                        yield ": keepalive\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                logger.unsubscribe(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/logs/stats")
    def logs_stats():
        stats = logger.get_stats()
        return {"status": "ok", **stats}

    # -----------------------------------------------------------------------
    # Health / Status
    # -----------------------------------------------------------------------
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

    # -----------------------------------------------------------------------
    # Projects API
    # -----------------------------------------------------------------------
    @app.get("/api/projects")
    def list_projects(include_deleted: bool = Query(False)):
        project_mgr = ProjectManager()
        return {
            "status": "ok",
            "active_project_id": project_mgr.get_active_project_id(),
            "projects": project_mgr.list_projects(include_deleted=include_deleted),
        }

    @app.post("/api/projects/select")
    def select_project(request: SelectProjectRequest):
        project_mgr = ProjectManager()
        success = project_mgr.set_active_project(request.project_id)
        if not success:
            logger.warning(
                "PROJECT", "project.select.failed",
                f"Attempted to select non-existent project: {request.project_id}",
                project_id=request.project_id,
                source="web.app",
            )
            raise HTTPException(status_code=404, detail="Project not found")

        logger.info(
            "PROJECT", "project.selected",
            f"Active project switched to: {request.project_id}",
            project_id=request.project_id,
            source="web.app",
        )

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
            logger.error(
                "PROJECT", "project.create.failed",
                f"Source zip file not found: {request.zip_path}",
                source="web.app",
                details={"zip_path": request.zip_path},
            )
            raise HTTPException(status_code=404, detail=f"Source zip file not found: {request.zip_path}")

        # Generate unique project_id
        timestamp_slug = Path(request.zip_path).stem
        project_id = f"proj_{timestamp_slug}"

        logger.info(
            "PROJECT", "project.create.started",
            f"Creating project \"{request.name}\" from {request.zip_path}",
            project_id=project_id,
            source="web.app",
            details={"name": request.name, "zip_path": request.zip_path},
        )

        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            ingestor.ingest_zip(str(target_path))
            snapshot = manager.get_project_snapshot(project_id)
        except Exception as exc:
            logger.error(
                "INGEST", "project.create.ingest_failed",
                f"Ingestion failed for project \"{request.name}\": {exc}",
                project_id=project_id,
                source="web.app",
                details={"error": str(exc)},
            )
            raise
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

        logger.info(
            "PROJECT", "project.created",
            f"Project \"{request.name}\" created successfully — {nodes} nodes, {rels} relationships",
            project_id=project_id,
            source="web.app",
            details={"name": request.name, "nodes": nodes, "relationships": rels, "zip_path": request.zip_path},
        )

        return {
            "status": "ok",
            "project": project_entry,
            "snapshot": snapshot,
        }

    @app.delete("/api/projects/{project_id}")
    def delete_project(project_id: str):
        project_mgr = ProjectManager()
        project_info = project_mgr.get_project(project_id)
        project_name = project_info.get("name", project_id) if project_info else project_id

        logger.info(
            "PROJECT", "project.delete.started",
            f"Deleting project \"{project_name}\" ({project_id}) — clearing graph data",
            project_id=project_id,
            source="web.app",
        )

        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            ingestor.clear_database(project_id=project_id)
        except Exception as exc:
            logger.error(
                "DATABASE", "project.delete.graph_clear_failed",
                f"Failed to clear graph data for project {project_id}: {exc}",
                project_id=project_id,
                source="web.app",
                details={"error": str(exc)},
            )
            raise
        finally:
            manager.close()

        success = project_mgr.delete_project(project_id)
        if not success:
            logger.warning(
                "PROJECT", "project.delete.registry_failed",
                f"Project {project_id} not found in registry after graph clear",
                project_id=project_id,
                source="web.app",
            )
            raise HTTPException(status_code=404, detail="Project not found in registry")

        logger.info(
            "PROJECT", "project.deleted",
            f"Project \"{project_name}\" ({project_id}) deleted — graph data and registry entry removed",
            project_id=project_id,
            source="web.app",
            details={"project_name": project_name},
        )

        runtime = _build_runtime_state(settings)
        return {
            "status": "ok",
            "deleted_project_id": project_id,
            "active_project_id": runtime["active_project_id"],
            "snapshot": runtime["snapshot"],
        }

    # -----------------------------------------------------------------------
    # Database
    # -----------------------------------------------------------------------
    @app.post("/api/neo4j/test")
    def test_neo4j_connection(req: TestDatabaseRequest):
        logger.info(
            "DATABASE", "config.database.test_started",
            f"Testing Neo4j connection to {req.uri}",
            source="web.app",
            details={"uri": req.uri, "username": req.username, "database": req.database},
        )

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

                logger.info(
                    "DATABASE", "config.database.tested",
                    f"Neo4j connection test succeeded — {nodes} nodes found at {req.uri}",
                    source="web.app",
                    details={"uri": req.uri, "nodes": nodes, "connected": True},
                )

                return {
                    "status": "ok",
                    "connected": True,
                    "nodes": nodes,
                    "message": f"Connected to {req.uri}",
                    "details": f"Total Nodes: {nodes}",
                }

            logger.warning(
                "DATABASE", "config.database.tested",
                f"Neo4j connection test failed for {req.uri} — unable to authenticate or connect",
                source="web.app",
                details={"uri": req.uri, "connected": False},
            )
            return {
                "status": "error",
                "connected": False,
                "message": "Connection failed. Check URI or credentials.",
                "details": "",
            }
        except Exception as exc:
            logger.error(
                "DATABASE", "config.database.test_error",
                f"Neo4j connection test error for {req.uri}: {exc}",
                source="web.app",
                details={"uri": req.uri, "error": str(exc)},
            )
            return {"status": "error", "connected": False, "message": str(exc), "details": ""}
        finally:
            test_mgr.close()

    # -----------------------------------------------------------------------
    # Ingest
    # -----------------------------------------------------------------------
    @app.post("/api/ingest")
    def ingest(request: IngestRequest):
        project_mgr = ProjectManager()
        project_id = request.project_id or project_mgr.get_active_project_id() or "proj_default"
        target_path = _resolve_project_path(request.zip_path)

        logger.info(
            "INGEST", "ingest.started",
            f"Ingestion started for {request.zip_path} into project {project_id}",
            project_id=project_id,
            source="web.app",
            details={"zip_path": str(target_path), "clear_database": request.clear_database},
        )

        manager = _db_manager(settings)
        try:
            ingestor = SharpHoundIngestor(manager, project_id=project_id)
            if request.clear_database:
                ingestor.clear_database(project_id=project_id)
                logger.info(
                    "DATABASE", "ingest.database_cleared",
                    f"Database cleared for project {project_id} before re-ingest",
                    project_id=project_id,
                    source="web.app",
                )
            ingestor.ingest_zip(str(target_path), project_id=project_id)
            snapshot = manager.get_project_snapshot(project_id)
        except Exception as exc:
            logger.error(
                "INGEST", "ingest.failed",
                f"Ingestion failed for {request.zip_path}: {exc}",
                project_id=project_id,
                source="web.app",
                details={"zip_path": str(target_path), "error": str(exc)},
            )
            raise
        finally:
            manager.close()

        project_mgr.update_project_stats(project_id, snapshot.get("nodes", 0), snapshot.get("relationships", 0))

        logger.info(
            "INGEST", "ingest.completed",
            f"Ingestion completed for {request.zip_path} — {snapshot.get('nodes', 0)} nodes, {snapshot.get('relationships', 0)} relationships",
            project_id=project_id,
            source="web.app",
            details={
                "zip_path": str(target_path),
                "nodes": snapshot.get("nodes", 0),
                "relationships": snapshot.get("relationships", 0),
            },
        )

        return {
            "status": "ok",
            "project_id": project_id,
            "zip_path": str(target_path),
            "cleared": request.clear_database,
            "snapshot": snapshot,
        }

    # -----------------------------------------------------------------------
    # Pathfinder
    # -----------------------------------------------------------------------
    @app.post("/api/pathfind")
    def pathfind(request: PathfindRequest):
        logger.info(
            "PATHFINDER", "pathfinder.started",
            f"Pathfinding [{request.mode}] {request.source_name} → {request.target_name}",
            source="web.app",
            details={"mode": request.mode, "source": request.source_name, "target": request.target_name},
        )

        manager = _db_manager(settings)
        try:
            coordinator = PathfinderCoordinator(manager)
            if request.mode == "predictive" and _load_predictive_model() is None:
                logger.error(
                    "PATHFINDER", "pathfinder.model_unavailable",
                    "Predictive model is not available for pathfinding",
                    source="web.app",
                )
                raise HTTPException(status_code=503, detail="Predictive model is not available.")

            results = coordinator.find_path(
                request.source_name,
                request.target_name,
                mode=request.mode,
                ml_model=_load_predictive_model() if request.mode == "predictive" else None,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "PATHFINDER", "pathfinder.failed",
                f"Pathfinding failed [{request.mode}] {request.source_name} → {request.target_name}: {exc}",
                source="web.app",
                details={"mode": request.mode, "error": str(exc)},
            )
            raise
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

        logger.info(
            "PATHFINDER", "pathfinder.completed",
            f"Pathfinding [{request.mode}] completed — {len(extracted)} path(s) found from {request.source_name} → {request.target_name}",
            source="web.app",
            details={
                "mode": request.mode,
                "source": request.source_name,
                "target": request.target_name,
                "result_count": len(extracted),
            },
        )

        return {
            "status": "ok",
            "mode": request.mode,
            "source_name": request.source_name.upper(),
            "target_name": request.target_name.upper(),
            "results": extracted,
            "result_count": len(extracted),
        }

    # -----------------------------------------------------------------------
    # Privesc
    # -----------------------------------------------------------------------
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
            logger.warning(
                "PRIVESC", "privesc.plan.no_path",
                "Privesc plan requested without a path selection",
                source="web.app",
            )
            raise HTTPException(status_code=400, detail="A path selection is required before building a privesc plan.")

        logger.info(
            "PRIVESC", "privesc.plan.started",
            "Building privilege escalation plan from selected attack path",
            source="web.app",
        )

        engine = PrivescEngine(None, settings.neo4j_database, settings.neo4j_uri, _make_privesc_context())
        try:
            engine.build_plan([{"p": path}])
        except Exception as exc:
            logger.error(
                "PRIVESC", "privesc.plan.failed",
                f"Privesc plan generation failed: {exc}",
                source="web.app",
                details={"error": str(exc)},
            )
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

        logger.info(
            "PRIVESC", "privesc.plan.completed",
            f"Privesc plan built — {len(tasks)} escalation task(s) identified",
            source="web.app",
            details={"total_steps": len(tasks)},
        )

        return {
            "status": "ok",
            "total_steps": len(tasks),
            "tasks": tasks,
        }

    # -----------------------------------------------------------------------
    # Remediation
    # -----------------------------------------------------------------------
    @app.post("/api/remediation")
    def remediation(request: RemediationRequest):
        logger.info(
            "REMEDIATION", "remediation.started",
            f"Generating remediation script for {len(request.targets)} target(s)",
            source="web.app",
            details={"target_count": len(request.targets)},
        )

        engine = RemediationEngine(output_dir=str(PROJECT_ROOT / "scripts"))
        success = engine.generate_script(request.targets)
        if not success:
            logger.error(
                "REMEDIATION", "remediation.failed",
                "No remediation script was generated — engine returned failure",
                source="web.app",
                details={"target_count": len(request.targets)},
            )
            raise HTTPException(status_code=400, detail="No remediation script was generated.")

        logger.info(
            "REMEDIATION", "remediation.completed",
            f"Remediation script generated — {len(request.targets)} target(s) mitigated → {engine.last_output_path}",
            source="web.app",
            details={
                "target_count": len(request.targets),
                "output_path": engine.last_output_path,
            },
        )

        return {
            "status": "ok",
            "generated": True,
            "output_path": engine.last_output_path,
            "target_count": len(request.targets),
        }

    return app