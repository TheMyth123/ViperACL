from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from utils.database import DatabaseManager

from .config import load_settings

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def build_neo4j_snapshot(settings):
    manager = DatabaseManager(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    snapshot = {
        "connected": False,
        "nodes": None,
        "relationships": None,
        "database": settings.neo4j_database,
        "uri": settings.neo4j_uri,
    }

    try:
        snapshot["connected"] = manager.connect()
        if snapshot["connected"]:
            node_result = manager.run_query("MATCH (n) RETURN count(n) AS node_count")
            rel_result = manager.run_query("MATCH ()-[r]->() RETURN count(r) AS relationship_count")
            if node_result:
                snapshot["nodes"] = node_result[0].get("node_count", 0)
            if rel_result:
                snapshot["relationships"] = rel_result[0].get("relationship_count", 0)
    finally:
        manager.close()

    return snapshot


def create_app():
    settings = load_settings()
    app = FastAPI(title=settings.title, version=settings.version)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        snapshot = build_neo4j_snapshot(settings)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "settings": settings,
                "snapshot": snapshot,
            },
        )

    @app.get("/api/health")
    def health():
        snapshot = build_neo4j_snapshot(settings)
        return {
            "status": "ok",
            "title": settings.title,
            "neo4j_connected": snapshot["connected"],
            "neo4j_database": snapshot["database"],
        }

    @app.get("/api/neo4j")
    def neo4j_status():
        return build_neo4j_snapshot(settings)

    return app