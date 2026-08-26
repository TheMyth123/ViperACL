"""System routes: health, database test, logs API, and SSE streaming."""

import asyncio
import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from core.database import DatabaseManager
from core.logger import logger
from web.helpers import build_runtime_state
from web.models import TestDatabaseRequest
from web.config import save_settings, load_settings

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Health / Status
# ---------------------------------------------------------------------------
@router.get("/health")
def health(request: Request):
    settings = request.app.state.settings
    runtime = build_runtime_state(settings)
    snapshot = runtime["snapshot"]
    return {
        "status": "ok",
        "title": settings.title,
        "version": settings.version,
        "model_available": runtime["model_available"],
        "model_name": runtime["model_name"],
        "model_type": runtime["model_type"],
        "model_status_text": runtime["model_status_text"],
        "ml_models": runtime.get("ml_models", []),
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


# ---------------------------------------------------------------------------
# Database Test
# ---------------------------------------------------------------------------
@router.post("/neo4j/test")
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


# ---------------------------------------------------------------------------
# Settings API
# ---------------------------------------------------------------------------
@router.post("/settings/save")
def save_user_settings(request: Request, payload: dict):
    logger.info(
        "SYSTEM", "config.settings.save",
        "Saving user settings to data/settings.json",
        source="web.app",
        details=payload
    )
    try:
        save_settings(payload)
        request.app.state.settings = load_settings()
        return {"status": "ok", "message": "Settings saved successfully."}
    except ValueError as exc:
        logger.error(
            "SYSTEM", "config.settings.validation_failed",
            f"Settings validation failed: {exc}",
            source="web.app",
            details={"error": str(exc)}
        )
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.error(
            "SYSTEM", "config.settings.error",
            f"Failed to save settings: {exc}",
            source="web.app",
            details={"error": str(exc)}
        )
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Logs API
# ---------------------------------------------------------------------------
@router.get("/logs")
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


@router.get("/logs/stream")
async def logs_stream():
    queue = logger.subscribe()

    async def event_generator():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(entry, default=str)}\n\n"
                except asyncio.TimeoutError:
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


@router.get("/logs/stats")
def logs_stats():
    stats = logger.get_stats()
    return {"status": "ok", **stats}
