import os
import re
import shutil
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from core.ingestor import SharpHoundIngestor, inspect_sharphound_zip
from core.logger import logger
from core.pathfinder.rules import normalize_path_dcsync
from core.privesc.path_utils import path_to_sequence
from core.privesc.state_context import SessionContext
from core.privesc.strict_executor import StrictPrivescExecutor, build_strict_action_plan
from core.projects import ProjectManager
from core.remediation.engine import RemediationEngine
from web.helpers import (
    PROJECT_ROOT, db_manager, make_privesc_context, resolve_project_path, serialize_node,
)
from web.models import ExecuteIngestRequest, IngestRequest, PrivescPlanRequest, RemediationRequest

router = APIRouter(prefix="/api")


@router.get("/tools/sharphound/download")
def download_sharphound():
    """Serves the SharpHound.exe collection binary for download."""
    tools_paths = [
        PROJECT_ROOT / "data" / "tools" / "SharpHound.exe",
        PROJECT_ROOT / "tools" / "SharpHound.exe",
        PROJECT_ROOT / "SharpHound.exe",
    ]
    for path in tools_paths:
        if path.exists() and path.is_file():
            logger.info(
                "SYSTEM", "tools.sharphound.downloaded",
                "SharpHound.exe collection binary downloaded",
                source="web.app",
                details={"file_size": path.stat().st_size},
            )
            return FileResponse(
                path=str(path),
                filename="SharpHound.exe",
                media_type="application/octet-stream",
            )

    logger.warning(
        "SYSTEM", "tools.sharphound.not_found",
        "SharpHound.exe download requested but binary not found in data/tools/",
        source="web.app",
    )
    raise HTTPException(
        status_code=404,
        detail="SharpHound.exe is not currently located in data/tools/. Please place the binary in data/tools/SharpHound.exe to enable direct downloads.",
    )


@router.post("/ingest/upload")
async def upload_ingest_archive(
    file: UploadFile = File(...),
    project_id: str | None = Form(None),
):
    """Uploads and inspects a SharpHound .zip archive without populating the graph database."""
    project_mgr = ProjectManager()
    target_project_id = project_id or project_mgr.get_active_project_id()
    if not target_project_id:
        raise HTTPException(
            status_code=400,
            detail="No active project selected. Please select or create a project first.",
        )

    # Validate filename extension
    filename = file.filename or "sharphound.zip"
    if not filename.lower().endswith(".zip"):
        logger.warning(
            "INGEST", "ingest.upload.invalid_extension",
            f"Uploaded file '{filename}' is not a .zip archive",
            project_id=target_project_id,
            source="web.app",
        )
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Only SharpHound .zip archives are supported.",
        )

    # Sanitize filename
    safe_filename = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)
    staging_dir = PROJECT_ROOT / "data" / "projects" / target_project_id / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    staged_path = staging_dir / safe_filename

    # Save uploaded file
    try:
        with staged_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as exc:
        logger.error(
            "INGEST", "ingest.upload.save_failed",
            f"Failed to write uploaded archive: {exc}",
            project_id=target_project_id,
            source="web.app",
        )
        raise HTTPException(status_code=500, detail="Failed to save uploaded archive.") from exc
    finally:
        await file.close()

    # Inspect the staged archive
    inspect_result = inspect_sharphound_zip(staged_path)
    if not inspect_result.get("valid"):
        # Remove invalid archive
        try:
            staged_path.unlink()
        except OSError:
            pass
        err_msg = inspect_result.get("error", "Invalid SharpHound archive structure.")
        logger.warning(
            "INGEST", "ingest.upload.invalid_archive",
            f"SharpHound archive validation failed: {err_msg}",
            project_id=target_project_id,
            source="web.app",
        )
        raise HTTPException(status_code=400, detail=err_msg)

    logger.info(
        "INGEST", "ingest.archive.inspected",
        f"SharpHound archive '{filename}' inspected successfully: domain={inspect_result.get('primary_domain')}, users={inspect_result['counts'].get('users', 0)}, computers={inspect_result['counts'].get('computers', 0)}",
        project_id=target_project_id,
        source="web.app",
        details={
            "filename": filename,
            "domain": inspect_result.get("primary_domain"),
            "counts": inspect_result.get("counts", {}),
            "file_size": inspect_result.get("file_size"),
        },
    )

    return {
        "status": "ok",
        "staged_path": str(staged_path.relative_to(PROJECT_ROOT)),
        "metadata": inspect_result,
    }


@router.post("/ingest/execute")
def execute_ingest(request: ExecuteIngestRequest, req: Request):
    """Executes graph ingestion from a staged or resolved SharpHound archive."""
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    project_id = request.project_id or project_mgr.get_active_project_id()
    if not project_id:
        raise HTTPException(
            status_code=400,
            detail="No active project selected. Please select or create a project first.",
        )

    target_path = resolve_project_path(request.staged_path)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Staged archive file not found.")

    logger.info(
        "INGEST", "ingest.execution_started",
        f"Starting database ingestion of '{target_path.name}' for project {project_id}",
        project_id=project_id,
        source="web.app",
        details={"path": str(target_path), "clear_database": request.clear_database},
    )

    manager = db_manager(settings)
    try:
        ingestor = SharpHoundIngestor(manager, project_id=project_id)
        if request.clear_database:
            ingestor.clear_database(project_id=project_id)
            logger.info(
                "DATABASE", "ingest.database_cleared",
                f"Graph partition cleared for project {project_id}",
                project_id=project_id,
                source="web.app",
            )
        ingestor.ingest_zip(str(target_path), project_id=project_id)
        snapshot = manager.get_project_snapshot(project_id)
    except Exception as exc:
        logger.error(
            "INGEST", "ingest.execution_failed",
            f"Ingestion failed: {exc}",
            project_id=project_id,
            source="web.app",
            details={"path": str(target_path), "error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Database ingestion error: {exc}") from exc
    finally:
        manager.close()

    # Auto-detect domain from archive inspection if project domain is not yet set
    try:
        inspect_result = inspect_sharphound_zip(target_path)
        primary_domain = inspect_result.get("primary_domain")
        proj = project_mgr.get_project(project_id)
        if primary_domain and proj and not proj.get("domain"):
            project_mgr.update_project_target(project_id, domain=primary_domain)
    except Exception:
        pass

    updated_proj = project_mgr.update_project_stats(
        project_id,
        snapshot.get("nodes", 0),
        snapshot.get("relationships", 0),
        source_zip=target_path.name,
    )

    logger.info(
        "INGEST", "ingest.completed",
        f"Ingestion completed: {snapshot.get('nodes', 0)} nodes, {snapshot.get('relationships', 0)} relationships in project {project_id}",
        project_id=project_id,
        source="web.app",
        details={
            "nodes": snapshot.get("nodes", 0),
            "relationships": snapshot.get("relationships", 0),
        },
    )

    return {
        "status": "ok",
        "project_id": project_id,
        "snapshot": snapshot,
        "project": updated_proj,
    }


@router.post("/ingest")
def legacy_ingest(request: IngestRequest, req: Request):
    """Backward-compatible ingest endpoint for direct paths."""
    exec_req = ExecuteIngestRequest(
        staged_path=request.zip_path,
        project_id=request.project_id,
        clear_database=request.clear_database,
    )
    return execute_ingest(exec_req, req)


@router.post("/privesc/plan")
def privesc_plan(request: PrivescPlanRequest, req: Request):
    settings = req.app.state.settings
    path = request.path
    if path:
        path = path_to_sequence(path)

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

    project_mgr = ProjectManager()
    active_id = project_mgr.get_active_project_id()
    project_info = project_mgr.get_project(active_id) if active_id else {}
    target_domain = (project_info.get("domain") or settings.neo4j_database or "DOMAIN.LOCAL") if project_info else settings.neo4j_database
    dc_ip = (project_info.get("dc_ip") or "127.0.0.1") if project_info else "127.0.0.1"
    foothold_user = (project_info.get("foothold_username") or "foothold") if project_info else "foothold"
    foothold_pass = (project_info.get("foothold_password") or "") if project_info else ""

    db = db_manager(settings)
    try:
        path = normalize_path_dcsync(path, db)
        plan = build_strict_action_plan(path, db)
    except Exception as exc:
        logger.error(
            "PRIVESC", "privesc.plan.failed",
            f"Privesc plan generation failed: {exc}",
            source="web.app",
            details={"error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        db.close()

    tasks = []
    for item in plan:
        tasks.append({
            "type": item["rel_type"],
            "module": item["action"],
            "source": serialize_node(item["start_node"]),
            "target": serialize_node(item["end_node"]),
            "step": item["step"],
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


@router.post("/privesc/execute")
def privesc_execute(request: PrivescPlanRequest, req: Request):
    """Execute a privesc plan against the target DC using project foothold credentials.

    Returns structured per-step results and collected logs.
    """
    path = request.path
    if path:
        path = path_to_sequence(path)

    if not path:
        raise HTTPException(status_code=400, detail="A path selection is required to execute an attack.")

    project_mgr = ProjectManager()
    active_id = project_mgr.get_active_project_id()
    project_info = project_mgr.get_project(active_id) if active_id else {}

    target_domain = (project_info.get("domain") or req.app.state.settings.neo4j_database or "DOMAIN.LOCAL") if project_info else req.app.state.settings.neo4j_database
    dc_ip = (project_info.get("dc_ip") or "127.0.0.1") if project_info else "127.0.0.1"
    foothold_user = (project_info.get("foothold_username") or "") if project_info else ""
    foothold_pass = (project_info.get("foothold_password") or "") if project_info else ""

    db = db_manager(req.app.state.settings)
    try:
        path = normalize_path_dcsync(path, db)
    finally:
        db.close()

    session_ctx = SessionContext(domain=target_domain, dc_ip=dc_ip, initial_user=foothold_user or "", initial_password=foothold_pass or "")

    import ldap3
    import io
    import sys
    import logging

    logs = []

    class ListHandler(logging.Handler):
        def emit(self, record):
            try:
                logs.append({"level": record.levelname, "message": self.format(record)})
            except Exception:
                pass

    list_handler = ListHandler()
    list_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(list_handler)

    stdout_buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = stdout_buf

    results = []
    success_overall = True

    try:
        server = ldap3.Server(dc_ip, use_ssl=True, get_info=None)

        def try_bind_variants(server, user, password, domain):
            """Try several common LDAP bind formats against the target DC."""
            last_exc = None
            candidates = []
            raw = (user or "")
            if raw:
                candidates.append(raw)
            if raw and "\\" not in raw and "@" not in raw:
                netbios = (domain.split(".")[0] if domain and "." in domain else domain) or None
                if netbios:
                    candidates.append(f"{netbios}\\{raw}")
                if domain:
                    candidates.append(f"{raw}@{domain}")

            for candidate in candidates:
                try:
                    return ldap3.Connection(server, user=candidate, password=password, auto_bind=True)
                except Exception as exc:
                    last_exc = exc

            try:
                return ldap3.Connection(server, user=raw, password=password, auto_bind=True)
            except Exception as exc:
                last_exc = exc

            raise last_exc

        try:
            conn = try_bind_variants(server, foothold_user or "", foothold_pass or "", target_domain)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"LDAP bind failed for foothold user: {exc}") from exc

        executor = StrictPrivescExecutor(conn=conn, domain=target_domain, dc_ip=dc_ip, context=session_ctx)
        execution = executor.execute_path(path)
        results = execution.get("steps", [])
        success_overall = bool(execution.get("success", False))

    finally:
        sys.stdout = old_stdout
        logging.getLogger().removeHandler(list_handler)
        stdout_text = stdout_buf.getvalue().strip()
        if stdout_text:
            logs.append({"level": "INFO", "message": stdout_text})

    return {
        "status": "ok",
        "success": success_overall,
        "steps": results,
        "logs": logs,
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
