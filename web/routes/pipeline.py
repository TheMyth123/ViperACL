"""Ingest, privesc plan, and remediation API routes."""

from fastapi import APIRouter, HTTPException, Request

from core.ingestor.parser import SharpHoundIngestor
from core.logger import logger
from core.privesc.engine import PrivescEngine
from core.projects import ProjectManager
from core.remediation.engine import RemediationEngine
from web.helpers import (
    PROJECT_ROOT, db_manager, make_privesc_context, resolve_project_path, serialize_node,
)
from web.models import IngestRequest, PrivescPlanRequest, RemediationRequest

router = APIRouter(prefix="/api")


@router.post("/ingest")
def ingest(request: IngestRequest, req: Request):
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    project_id = request.project_id or project_mgr.get_active_project_id() or "proj_default"
    target_path = resolve_project_path(request.zip_path)

    logger.info(
        "INGEST", "ingest.started",
        f"Ingestion started for {request.zip_path} into project {project_id}",
        project_id=project_id,
        source="web.app",
        details={"zip_path": str(target_path), "clear_database": request.clear_database},
    )

    manager = db_manager(settings)
    try:
        ingestor = SharpHoundIngestor(manager, project_id=project_id)
        if request.clear_database:
            ingestor.clear_database(project_id=project_id)
            logger.info(
                "DATABASE", "ingest.database_cleared",
                f"Database cleared for project {project_id} before re-ingest",
                project_id=project_id,
                source="web.app",
            )
        ingestor.ingest_zip(str(target_path), project_id=project_id)
        snapshot = manager.get_project_snapshot(project_id)
    except Exception as exc:
        logger.error(
            "INGEST", "ingest.failed",
            f"Ingestion failed for {request.zip_path}: {exc}",
            project_id=project_id,
            source="web.app",
            details={"zip_path": str(target_path), "error": str(exc)},
        )
        raise
    finally:
        manager.close()

    project_mgr.update_project_stats(project_id, snapshot.get("nodes", 0), snapshot.get("relationships", 0))

    logger.info(
        "INGEST", "ingest.completed",
        f"Ingestion completed for {request.zip_path} — {snapshot.get('nodes', 0)} nodes, {snapshot.get('relationships', 0)} relationships",
        project_id=project_id,
        source="web.app",
        details={
            "zip_path": str(target_path),
            "nodes": snapshot.get("nodes", 0),
            "relationships": snapshot.get("relationships", 0),
        },
    )

    return {
        "status": "ok",
        "project_id": project_id,
        "zip_path": str(target_path),
        "cleared": request.clear_database,
        "snapshot": snapshot,
    }


@router.post("/privesc/plan")
def privesc_plan(request: PrivescPlanRequest, req: Request):
    settings = req.app.state.settings
    path = request.path
    if isinstance(path, dict):
        if "sequence" in path:
            path = path["sequence"]
        elif "steps" in path:
            sequence = []
            for step in path["steps"]:
                sequence.append(step.get("source", {}))
                sequence.append(step.get("relationship"))
                sequence.append(step.get("target", {}))
            path = sequence

    if not path:
        logger.warning(
            "PRIVESC", "privesc.plan.no_path",
            "Privesc plan requested without a path selection",
            source="web.app",
        )
        raise HTTPException(status_code=400, detail="A path selection is required before building a privesc plan.")

    logger.info(
        "PRIVESC", "privesc.plan.started",
        "Building privilege escalation plan from selected attack path",
        source="web.app",
    )

    engine = PrivescEngine(None, settings.neo4j_database, settings.neo4j_uri, make_privesc_context())
    try:
        engine.build_plan([{"p": path}])
    except Exception as exc:
        logger.error(
            "PRIVESC", "privesc.plan.failed",
            f"Privesc plan generation failed: {exc}",
            source="web.app",
            details={"error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    tasks = []
    for rel, module in engine.task_queue:
        tasks.append({
            "type": rel.type,
            "module": module.__class__.__name__,
            "source": serialize_node(getattr(rel, "start_node", None)),
            "target": serialize_node(getattr(rel, "end_node", None)),
        })

    logger.info(
        "PRIVESC", "privesc.plan.completed",
        f"Privesc plan built — {len(tasks)} escalation task(s) identified",
        source="web.app",
        details={"total_steps": len(tasks)},
    )

    return {
        "status": "ok",
        "total_steps": len(tasks),
        "tasks": tasks,
    }


@router.post("/remediation")
def remediation(request: RemediationRequest):
    logger.info(
        "REMEDIATION", "remediation.started",
        f"Generating remediation script for {len(request.targets)} target(s)",
        source="web.app",
        details={"target_count": len(request.targets)},
    )

    engine = RemediationEngine(output_dir=str(PROJECT_ROOT / "scripts"))
    success = engine.generate_script(request.targets)
    if not success:
        logger.error(
            "REMEDIATION", "remediation.failed",
            "No remediation script was generated — engine returned failure",
            source="web.app",
            details={"target_count": len(request.targets)},
        )
        raise HTTPException(status_code=400, detail="No remediation script was generated.")

    logger.info(
        "REMEDIATION", "remediation.completed",
        f"Remediation script generated — {len(request.targets)} target(s) mitigated → {engine.last_output_path}",
        source="web.app",
        details={
            "target_count": len(request.targets),
            "output_path": engine.last_output_path,
        },
    )

    return {
        "status": "ok",
        "generated": True,
        "output_path": engine.last_output_path,
        "target_count": len(request.targets),
    }
