from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core.logger import logger
from web.config import load_settings
from web.helpers import build_runtime_state
from web.routes import pages, pathfinder, pipeline, projects, system

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup log
    logger.info(
        "SYSTEM", "system.startup",
        f"ViperACL v{app.state.settings.version} starting — Neo4j target: {app.state.settings.neo4j_uri}",
        source="web.app",
        details={"neo4j_uri": app.state.settings.neo4j_uri, "neo4j_database": app.state.settings.neo4j_database},
    )
    yield
    # Clean shutdown log
    logger.info(
        "SYSTEM", "system.shutdown",
        "ViperACL web application shutting down cleanly",
        source="web.app",
    )


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(title=settings.title, version=settings.version, lifespan=lifespan)
    app.state.settings = settings
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    # Register custom exception handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        # If API request or JSON requested, return clean JSON
        if request.url.path.startswith("/api") or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(status_code=exc.status_code, content={"status": "error", "detail": exc.detail})

        runtime = build_runtime_state(request.app.state.settings)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "active_page": "error",
                "settings": request.app.state.settings,
                "snapshot": runtime.get("snapshot", {}),
                "runtime": runtime,
                "error_code": exc.status_code,
                "error_title": "Service Unavailable" if exc.status_code == 503 else "Resource Not Found" if exc.status_code == 404 else "Application Error",
                "error_message": exc.detail,
            },
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.error(
            "SYSTEM", "system.unhandled_exception",
            f"Unhandled exception at {request.url.path}: {exc}",
            source="web.app",
            details={"path": request.url.path, "error": str(exc)},
        )
        if request.url.path.startswith("/api") or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(status_code=500, content={"status": "error", "detail": "Internal Server Error"})

        runtime = build_runtime_state(request.app.state.settings)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "active_page": "error",
                "settings": request.app.state.settings,
                "snapshot": runtime.get("snapshot", {}),
                "runtime": runtime,
                "error_code": 500,
                "error_title": "Internal Server Error",
                "error_message": "An unexpected error occurred while processing this request.",
            },
            status_code=500,
        )

    # Register route modules
    app.include_router(pages.router)
    app.include_router(system.router)
    app.include_router(projects.router)
    app.include_router(pathfinder.router)
    app.include_router(pipeline.router)

    return app


app = create_app()