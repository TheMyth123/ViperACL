"""Project CRUD API routes."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

from core.ingestor.parser import SharpHoundIngestor
from core.logger import logger
from core.projects import ProjectManager, validate_project_name, generate_safe_project_id
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
        "redirect_url": "/workspace",
    }


@router.post("/create")
def create_project(request: CreateProjectRequest, req: Request):
    valid, result = validate_project_name(request.name)
    if not valid:
        logger.warning(
            "PROJECT", "project.create.invalid_name",
            f"Project creation rejected due to invalid name: {result}",
            source="web.app",
            details={"raw_name": request.name, "error": result},
        )
        raise HTTPException(status_code=400, detail=result)

    cleaned_name = result
    project_mgr = ProjectManager()

    # Duplicate check across ALL projects (both active and soft-deleted)
    if project_mgr.project_name_exists(cleaned_name):
        logger.warning(
            "PROJECT", "project.create.duplicate_name",
            f"Project creation rejected: duplicate name \"{cleaned_name}\" (unique name required across active and archived records)",
            source="web.app",
            details={"name": cleaned_name},
        )
        raise HTTPException(
            status_code=409,
            detail="Project name duplicate. Choose a new name.",
        )

    # Generate a safe, collision-resistant project ID
    project_id = generate_safe_project_id(cleaned_name)

    # Register project with clean initial state (0 nodes, 0 rels, no zip yet)
    project_entry = project_mgr.register_project(
        project_id=project_id,
        name=cleaned_name,
        source_zip=None,
        nodes=0,
        relationships=0,
    )

    logger.info(
        "PROJECT", "project.created",
        f"Project \"{cleaned_name}\" created successfully (ID: {project_id})",
        project_id=project_id,
        source="web.app",
        details={"name": cleaned_name, "project_id": project_id},
    )

    return {
        "status": "ok",
        "project": project_entry,
        "active_project_id": project_id,
        "redirect_url": "/workspace",
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
