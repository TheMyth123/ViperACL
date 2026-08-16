"""HTML page routes."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from core.logger import logger
from core.projects import ProjectManager
from web.helpers import build_runtime_state, BASE_DIR

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def launchpad(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
    logger.debug(
        "SYSTEM", "system.launchpad.loaded",
        "Launchpad page loaded",
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


@router.get("/workspace", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
def workspace_page(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
    project_mgr = ProjectManager()
    active_project_id = project_mgr.get_active_project_id()
    active_project = project_mgr.get_project(active_project_id) if active_project_id else None

    ingest_metadata = None
    if active_project and active_project.get("source_zip") and active_project_id:
        source_zip_name = active_project["source_zip"]
        possible_paths = [
            BASE_DIR.parent / "data" / "projects" / active_project_id / "staging" / source_zip_name,
            BASE_DIR.parent / "dev" / source_zip_name,
            BASE_DIR.parent / source_zip_name,
        ]
        for p in possible_paths:
            if p.exists():
                try:
                    from core.ingestor import inspect_sharphound_zip
                    ingest_metadata = inspect_sharphound_zip(p)
                    break
                except Exception:
                    pass

    logger.debug(
        "SYSTEM", "system.workspace.loaded",
        f"Tactical Workspace loaded (Active Project: {active_project_id or 'None'})",
        project_id=active_project_id,
        source="web.app",
    )
    return templates.TemplateResponse(
        request,
        "workspace.html",
        {
            "active_page": "workspace",
            "settings": settings,
            "snapshot": runtime["snapshot"],
            "runtime": runtime,
            "active_project": active_project,
            "active_project_id": active_project_id,
            "ingest_metadata": ingest_metadata,
        },
    )


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
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


@router.get("/sharphound", response_class=HTMLResponse)
def sharphound_page(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
    project_mgr = ProjectManager()
    active_project_id = project_mgr.get_active_project_id()
    active_project = project_mgr.get_project(active_project_id) if active_project_id else None

    logger.debug(
        "SYSTEM", "system.sharphound_page.loaded",
        "SharpHound collector download and guide page loaded",
        project_id=active_project_id,
        source="web.app",
    )
    return templates.TemplateResponse(
        request,
        "sharphound.html",
        {
            "active_page": "sharphound",
            "settings": settings,
            "snapshot": runtime["snapshot"],
            "runtime": runtime,
            "active_project": active_project,
            "active_project_id": active_project_id,
        },
    )


