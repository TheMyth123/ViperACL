"""HTML page routes."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from core.logger import logger
from web.helpers import build_runtime_state, BASE_DIR

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
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
