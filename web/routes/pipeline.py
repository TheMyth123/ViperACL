import os
import re
import shutil
from datetime import datetime
from pathlib import Path
import socket

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
from web.models import (
    ExecuteIngestRequest,
    GenerateRemediationRequest,
    IngestRequest,
    PrivescPlanRequest,
    RemediationRequest,
)

router = APIRouter(prefix="/api")


def ping_dc(dc_ip: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Return True when the target DC is reachable on a standard AD service port."""
    if not dc_ip:
        return False
    try:
        with socket.create_connection((str(dc_ip), int(port)), timeout=timeout):
            return True
    except OSError:
        return False


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

    # Sanitize and timestamp filename for chronological sorting
    raw_safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    if not re.match(r"^\d{14}_", raw_safe_name):
        safe_filename = f"{timestamp}_{raw_safe_name}"
    else:
        safe_filename = raw_safe_name

    project_dir = project_mgr.get_project_dir(target_project_id)
    staging_dir = project_dir / "staging"
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

    # Auto-detect domain from archive inspection and update project target domain
    try:
        inspect_result = inspect_sharphound_zip(target_path)
        primary_domain = inspect_result.get("primary_domain")
        if primary_domain and primary_domain != "UNKNOWN.LOCAL":
            project_mgr.update_project_target(project_id, domain=primary_domain)
    except Exception:
        pass

    updated_proj = project_mgr.reset_project_pipeline_on_reingest(
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

    project_mgr = ProjectManager()
    active_id = request.project_id or project_mgr.get_active_project_id()

    if not path:
        logger.warning(
            "PRIVESC", "privesc.plan.no_path",
            "Privesc plan requested without a path selection",
            project_id=active_id,
            source="web.app",
        )
        raise HTTPException(status_code=400, detail="A path selection is required before building a privesc plan.")

    logger.info(
        "PRIVESC", "privesc.plan.started",
        "Building privilege escalation plan from selected attack path",
        project_id=active_id,
        source="web.app",
        details={"path_steps": len(path.get("steps", [])) if isinstance(path, dict) else len(path or [])},
    )

    project_info = project_mgr.get_project(active_id) if active_id else {}
    target_domain = (project_info.get("domain") or settings.neo4j_database or "DOMAIN.LOCAL") if project_info else settings.neo4j_database
    dc_ip = (project_info.get("dc_ip") or "127.0.0.1") if project_info else "127.0.0.1"
    foothold_user = (project_info.get("foothold_username") or "foothold") if project_info else "foothold"
    foothold_pass = (project_info.get("foothold_password") or "") if project_info else ""

    db = db_manager(settings)
    try:
        path = normalize_path_dcsync(path, db, project_id=active_id)
        plan = build_strict_action_plan(path, db, project_id=active_id)
    except Exception as exc:
        logger.error(
            "PRIVESC", "privesc.plan.failed",
            f"Privesc plan generation failed: {exc}",
            project_id=active_id,
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
        project_id=active_id,
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

    project_mgr = ProjectManager()
    active_id = request.project_id or project_mgr.get_active_project_id()

    if not path:
        raise HTTPException(status_code=400, detail="A path selection is required to execute an attack.")

    project_info = project_mgr.get_project(active_id) if active_id else {}

    target_domain = (project_info.get("domain") or req.app.state.settings.neo4j_database or "DOMAIN.LOCAL") if project_info else req.app.state.settings.neo4j_database
    dc_ip = (project_info.get("dc_ip") or "127.0.0.1") if project_info else "127.0.0.1"
    foothold_user = (project_info.get("foothold_username") or "") if project_info else ""
    foothold_pass = (project_info.get("foothold_password") or "") if project_info else ""

    db = db_manager(req.app.state.settings)
    try:
        path = normalize_path_dcsync(path, db, project_id=active_id)
    finally:
        db.close()

    session_ctx = SessionContext(domain=target_domain, dc_ip=dc_ip, initial_user=foothold_user or "", initial_password=foothold_pass or "")
    session_ctx.project_id = active_id

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
        if not ping_dc(dc_ip):
            logger.error(
                "PRIVESC",
                "privesc.dc_ping.failed",
                f"DC reachability check failed for {dc_ip} before attack execution",
                project_id=active_id,
                source="web.app",
                details={"dc_ip": dc_ip},
            )
            raise HTTPException(status_code=503, detail="DC connectivity check failed — attack aborted before execution.")

        logger.info(
            "PRIVESC",
            "privesc.dc_ping.success",
            f"DC reachability check succeeded for {dc_ip} before attack execution",
            project_id=active_id,
            source="web.app",
            details={"dc_ip": dc_ip},
        )

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
            logger.error(
                "AUTH",
                "auth.foothold_bind.failed",
                "Failed to bind with foothold user. Check the foothold user credentials and domain.",
                project_id=active_id,
                source="web.app",
                details={
                    "dc_ip": dc_ip,
                    "domain": target_domain,
                    "foothold_user": foothold_user or "",
                    "error": "bind_failed",
                },
            )
            raise HTTPException(
                status_code=400,
                detail="Failed to bind with foothold user. Check the foothold user credentials and domain.",
            ) from exc

        executor = StrictPrivescExecutor(
            conn=conn,
            domain=target_domain,
            dc_ip=dc_ip,
            context=session_ctx,
            default_reset_password=getattr(req.app.state.settings, "privesc_default_change_password", "Secur3P@ssw0rd!"),
        )
        execution = executor.execute_path(path)
        results = execution.get("steps", [])
        success_overall = bool(execution.get("success", False))

        if success_overall and active_id and results:
            final_step = results[-1]
            final_target = final_step.get("target") or ""
            final_relationship = final_step.get("type") or ""
            final_target_type = str(final_step.get("target_type") or "").lower()
            final_proof = final_step.get("proof_value") or ""
            success_record = {
                "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "kind": final_target_type or (final_relationship or "").lower(),
                "target": final_target,
                "relationship": final_relationship,
                "proof_value": final_proof,
                "step_count": len(results),
                "source": request.path.get("steps", [{}])[0].get("source", {}).get("name") if isinstance(request.path, dict) and request.path.get("steps") else "",
            }
            updated_project = project_mgr.append_privesc_success_record(active_id, success_record)
            if updated_project:
                logger.info(
                    "PRIVESC",
                    "privesc.success_record.saved",
                    f"Saved successful privesc result record for project {active_id}",
                    project_id=active_id,
                    source="web.app",
                    details={"target": final_target, "kind": success_record["kind"]},
                )

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
        "success_record": success_record if success_overall and active_id and results else None,
    }


@router.post("/remediation/generate")
def generate_remediation_script(request: GenerateRemediationRequest, req: Request):
    """Generates a surgical Active Directory PowerShell remediation script.

    Saves the script to the project storage directory, persists metadata in projects.json,
    and logs structured forensic evidence.
    """
    project_mgr = ProjectManager()
    project_id = request.project_id or project_mgr.get_active_project_id()
    if not project_id:
        raise HTTPException(
            status_code=400,
            detail="No active project selected. Please select or create a project first.",
        )

    project = project_mgr.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Active project not found.")

    if not request.targets:
        raise HTTPException(
            status_code=400,
            detail="No remediation targets were selected. Please select at least one relationship to remediate.",
        )

    # Set up project-specific scripts directory: data/projects/storage/{project_id}/scripts/
    project_dir = project_mgr.get_project_dir(project_id)
    scripts_dir = project_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    project_name = project.get("name", "Active Assessment")
    domain_name = project.get("domain") or getattr(req.app.state.settings, "neo4j_database", "DOMAIN.LOCAL")

    logger.info(
        "REMEDIATION", "remediation.script_generation_started",
        f"Generating remediation script for {len(request.targets)} target(s) in project {project_id}",
        project_id=project_id,
        source="web.app",
        details={
            "target_count": len(request.targets),
            "total_path_steps": len(request.all_edges) if request.all_edges else len(request.targets),
            "project_name": project_name,
            "domain": domain_name,
        },
    )

    engine = RemediationEngine(output_dir=str(scripts_dir))
    gen_result = engine.generate_script(
        remediation_targets=request.targets,
        project_name=project_name,
        domain=domain_name,
        project_root=PROJECT_ROOT,
    )

    if not gen_result.get("success"):
        err_msg = gen_result.get("error", "Remediation engine failed to generate script.")
        logger.error(
            "REMEDIATION", "remediation.script_generation_failed",
            f"Remediation script generation failed: {err_msg}",
            project_id=project_id,
            source="web.app",
            details={"error": err_msg},
        )
        raise HTTPException(status_code=400, detail=err_msg)

    # Determine included vs excluded edges based on request.all_edges
    included_indices = {
        t.get("index") for t in request.targets if t.get("index") is not None
    }
    
    included_edges = []
    excluded_edges = []
    
    if request.all_edges:
        for idx, edge in enumerate(request.all_edges):
            edge_idx = edge.get("index", idx)
            # Check if this edge is in targets
            is_included = (edge_idx in included_indices) or any(
                t.get("source") == edge.get("source") and
                t.get("type") == (edge.get("type") or edge.get("relationship")) and
                t.get("target") == edge.get("target")
                for t in request.targets
            )
            edge_copy = dict(edge)
            edge_copy["index"] = edge_idx
            edge_copy["included"] = is_included
            if is_included:
                included_edges.append(edge_copy)
            else:
                excluded_edges.append(edge_copy)
    else:
        included_edges = request.targets
        excluded_edges = []

    now_id_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    script_id = f"rem_{project_id}_{now_id_timestamp}"

    script_record = {
        "id": script_id,
        "filename": gen_result["filename"],
        "created_at": gen_result["created_at"],
        "relative_path": gen_result["relative_path"],
        "file_size": gen_result["file_size"],
        "target_count": gen_result["target_count"],
        "total_path_steps": len(request.all_edges) if request.all_edges else gen_result["target_count"],
        "included_edges": included_edges,
        "excluded_edges": excluded_edges,
        "all_edges": request.all_edges or [],
        "path_summary": request.path_summary or {},
        "script_content": gen_result["script_content"],
    }

    # Persist in projects.json
    project_mgr.add_remediation_script(project_id, script_record)

    logger.info(
        "REMEDIATION", "remediation.script_generated",
        f"Remediation script '{gen_result['filename']}' generated and archived ({gen_result['target_count']} action(s), {gen_result['file_size']} bytes)",
        project_id=project_id,
        source="web.app",
        details={
            "script_id": script_id,
            "filename": gen_result["filename"],
            "target_count": gen_result["target_count"],
            "file_size": gen_result["file_size"],
            "output_path": gen_result["output_path"],
        },
    )

    return {
        "status": "ok",
        "script": script_record,
        "scripts": project_mgr.get_remediation_scripts(project_id),
    }


@router.get("/remediation/scripts")
def list_remediation_scripts(project_id: str | None = None):
    """Lists all archived remediation scripts for the active (or specified) project."""
    project_mgr = ProjectManager()
    target_project_id = project_id or project_mgr.get_active_project_id()
    if not target_project_id:
        return {"status": "ok", "scripts": []}

    scripts = project_mgr.get_remediation_scripts(target_project_id)
    return {"status": "ok", "project_id": target_project_id, "scripts": scripts}


@router.get("/remediation/scripts/{script_id}")
def get_remediation_script(script_id: str, project_id: str | None = None):
    """Retrieves a specific archived remediation script by its ID."""
    project_mgr = ProjectManager()
    target_project_id = project_id or project_mgr.get_active_project_id()
    if not target_project_id:
        raise HTTPException(status_code=400, detail="No active project selected.")

    script = project_mgr.get_remediation_script_by_id(target_project_id, script_id)
    if not script:
        raise HTTPException(status_code=404, detail="Remediation script record not found.")

    # Read script file content from disk if not present in memory
    if not script.get("script_content") and script.get("relative_path"):
        file_path = resolve_project_path(script["relative_path"])
        if file_path.exists():
            try:
                script["script_content"] = file_path.read_text(encoding="utf-8")
            except Exception:
                pass

    return {"status": "ok", "script": script}


@router.get("/remediation/scripts/{script_id}/download")
def download_remediation_script(script_id: str, project_id: str | None = None):
    """Serves the generated PowerShell script (.ps1) as a direct file download."""
    project_mgr = ProjectManager()
    target_project_id = project_id or project_mgr.get_active_project_id()
    if not target_project_id:
        raise HTTPException(status_code=400, detail="No active project selected.")

    script = project_mgr.get_remediation_script_by_id(target_project_id, script_id)
    if not script:
        raise HTTPException(status_code=404, detail="Remediation script record not found.")

    filename = script.get("filename") or f"{script_id}.ps1"
    rel_path = script.get("relative_path")
    if not rel_path:
        raise HTTPException(status_code=404, detail="Script path is missing from registry.")

    file_path = resolve_project_path(rel_path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Remediation script file not found on disk.")

    logger.info(
        "REMEDIATION", "remediation.script_downloaded",
        f"Remediation script '{filename}' downloaded",
        project_id=target_project_id,
        source="web.app",
        details={"script_id": script_id, "filename": filename, "file_size": file_path.stat().st_size},
    )

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/remediation")
def legacy_remediation(request: RemediationRequest, req: Request):
    """Backward-compatible remediation endpoint."""
    gen_req = GenerateRemediationRequest(
        targets=request.targets,
        all_edges=request.targets,
    )
    return generate_remediation_script(gen_req, req)

