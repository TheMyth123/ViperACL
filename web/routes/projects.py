"""Project CRUD API routes."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

from core.ingestor.parser import SharpHoundIngestor
from core.logger import logger
from core.projects import ProjectManager
from web.helpers import build_runtime_state, build_neo4j_snapshot, db_manager, resolve_project_path
from web.models import SelectProjectRequest, CreateProjectRequest

router = APIRouter(prefix="/api/projects")


@router.get("")
def list_projects(include_deleted: bool = Query(False)):
    project_mgr = ProjectManager()
    return {
        "status": "ok",
        "active_project_id": project_mgr.get_active_project_id(),
        "projects": project_mgr.list_projects(include_deleted=include_deleted),
    }


@router.post("/select")
def select_project(request: SelectProjectRequest, req: Request):
    settings = req.app.state.settings
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

    runtime = build_runtime_state(settings)
    return {
        "status": "ok",
        "active_project_id": request.project_id,
        "project": project_mgr.get_project(request.project_id),
        "snapshot": runtime["snapshot"],
    }


@router.post("/create")
def create_project(request: CreateProjectRequest, req: Request):
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    target_path = resolve_project_path(request.zip_path)
    if not target_path.exists():
        logger.error(
            "PROJECT", "project.create.failed",
            f"Source zip file not found: {request.zip_path}",
            source="web.app",
            details={"zip_path": request.zip_path},
        )
        raise HTTPException(status_code=404, detail=f"Source zip file not found: {request.zip_path}")

    timestamp_slug = Path(request.zip_path).stem
    project_id = f"proj_{timestamp_slug}"

    logger.info(
        "PROJECT", "project.create.started",
        f"Creating project \"{request.name}\" from {request.zip_path}",
        project_id=project_id,
        source="web.app",
        details={"name": request.name, "zip_path": request.zip_path},
    )

    manager = db_manager(settings)
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


@router.delete("/{project_id}")
def delete_project(project_id: str, req: Request):
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    project_info = project_mgr.get_project(project_id)
    project_name = project_info.get("name", project_id) if project_info else project_id

    logger.info(
        "PROJECT", "project.delete.started",
        f"Deleting project \"{project_name}\" ({project_id}) — clearing graph data",
        project_id=project_id,
        source="web.app",
    )

    manager = db_manager(settings)
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

    runtime = build_runtime_state(settings)
    return {
        "status": "ok",
        "deleted_project_id": project_id,
        "active_project_id": runtime["active_project_id"],
        "snapshot": runtime["snapshot"],
    }
