"""Pathfinder API route."""

from fastapi import APIRouter, HTTPException, Request

from core.logger import logger
from core.pathfinder.pathfinder import PathfinderCoordinator
from web.helpers import db_manager, load_predictive_model, summarize_path
from web.models import PathfindRequest

router = APIRouter(prefix="/api")


@router.post("/pathfind")
def pathfind(request: PathfindRequest, req: Request):
    settings = req.app.state.settings
    from core.projects import ProjectManager
    project_mgr = ProjectManager()
    project_id = request.project_id or project_mgr.get_active_project_id()

    logger.info(
        "PATHFINDER", "pathfinder.started",
        f"Pathfinding [{request.mode}] {request.source_name} → {request.target_name}",
        project_id=project_id,
        source="web.app",
        details={"mode": request.mode, "source": request.source_name, "target": request.target_name, "project_id": project_id},
    )

    manager = db_manager(settings)
    try:
        coordinator = PathfinderCoordinator(manager)
        if request.mode == "predictive" and load_predictive_model() is None:
            logger.error(
                "PATHFINDER", "pathfinder.model_unavailable",
                "Predictive model is not available for pathfinding",
                project_id=project_id,
                source="web.app",
            )
            raise HTTPException(status_code=503, detail="Predictive model is not available.")

        results = coordinator.find_path(
            request.source_name,
            request.target_name,
            mode=request.mode,
            ml_model=load_predictive_model() if request.mode == "predictive" else None,
            max_hops=settings.pathfinder_max_hops,
            ml_threshold=settings.pathfinder_ml_threshold,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "PATHFINDER", "pathfinder.failed",
            f"Pathfinding failed [{request.mode}] {request.source_name} → {request.target_name}: {exc}",
            project_id=project_id,
            source="web.app",
            details={"mode": request.mode, "error": str(exc), "project_id": project_id},
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
        summary = summarize_path(path, metrics=metrics, score=record.get("success_probability"))
        extracted.append({
            **summary,
            "metrics": metrics,
            "success_probability": record.get("success_probability"),
            "pathWeight": record.get("pathWeight"),
            "hops": record.get("hops"),
        })

    logger.info(
        "PATHFINDER", "pathfinder.completed",
        f"Pathfinding [{request.mode}] completed — {len(extracted)} path(s) found from {request.source_name} → {request.target_name}",
        project_id=project_id,
        source="web.app",
        details={
            "mode": request.mode,
            "source": request.source_name,
            "target": request.target_name,
            "result_count": len(extracted),
            "project_id": project_id,
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


@router.get("/nodes/search")
def search_nodes(q: str, req: Request):
    if not q or len(q.strip()) < 1:
        return {"status": "ok", "results": []}
        
    settings = req.app.state.settings
    manager = db_manager(settings)
    
    try:
        if not manager.connect():
            raise HTTPException(status_code=503, detail="Database not connected")
            
        # Prioritize exact match, prefix match, Domain root, then Users/Groups/Computers
        query = """
        MATCH (n)
        WHERE n.name IS NOT NULL AND toUpper(n.name) CONTAINS toUpper($q)
        WITH DISTINCT n.name AS name,
          CASE 
            WHEN toUpper(n.name) = toUpper($q) THEN 1
            WHEN toUpper(n.name) STARTS WITH toUpper($q) THEN 2
            WHEN 'Domain' IN labels(n) THEN 3
            WHEN 'User' IN labels(n) THEN 4
            WHEN 'Group' IN labels(n) THEN 5
            WHEN 'Computer' IN labels(n) THEN 6
            ELSE 7
          END AS priority
        RETURN name
        ORDER BY priority ASC, size(name) ASC, name ASC
        LIMIT 25
        """
        results = manager.run_query(query, {"q": q})
        names = [r["name"] for r in results if r.get("name")]
        
        return {"status": "ok", "results": names}
    except Exception as exc:
        logger.error(
            "PATHFINDER", "nodes.search.error",
            f"Error searching nodes for {q}: {exc}",
            source="web.app"
        )
        return {"status": "error", "results": []}
    finally:
        manager.close()
