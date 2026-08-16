"""ViperACL web application factory."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from core.logger import logger
from web.config import load_settings
from web.routes import pages, pathfinder, pipeline, projects, system

BASE_DIR = Path(__file__).resolve().parent


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(title=settings.title, version=settings.version)
    app.state.settings = settings
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    # Register route modules
    app.include_router(pages.router)
    app.include_router(system.router)
    app.include_router(projects.router)
    app.include_router(pathfinder.router)
    app.include_router(pipeline.router)

    # Log application startup
    logger.info(
        "SYSTEM", "system.startup",
        f"ViperACL v{settings.version} starting — Neo4j target: {settings.neo4j_uri}",
        source="web.app",
        details={"neo4j_uri": settings.neo4j_uri, "neo4j_database": settings.neo4j_database},
    )

    return app