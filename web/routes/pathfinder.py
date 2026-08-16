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

    logger.info(
        "PATHFINDER", "pathfinder.started",
        f"Pathfinding [{request.mode}] {request.source_name} → {request.target_name}",
        source="web.app",
        details={"mode": request.mode, "source": request.source_name, "target": request.target_name},
    )

    manager = db_manager(settings)
    try:
        coordinator = PathfinderCoordinator(manager)
        if request.mode == "predictive" and load_predictive_model() is None:
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
            ml_model=load_predictive_model() if request.mode == "predictive" else None,
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
