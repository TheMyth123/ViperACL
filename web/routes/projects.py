import socket
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

from core.ingestor.parser import SharpHoundIngestor
from core.logger import logger
from core.projects import ProjectManager, validate_project_name, generate_safe_project_id
from web.helpers import build_runtime_state, build_neo4j_snapshot, db_manager, resolve_project_path
from web.models import (
    SelectProjectRequest,
    CreateProjectRequest,
    UpdateProjectTargetRequest,
    TestPingRequest,
    TestFootholdRequest,
    UnlockPhaseRequest,
    SavePathRequest,
    SetActivePhaseRequest,
)

router = APIRouter(prefix="/api/projects")


def ping_target_dc(dc_ip: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Check TCP connectivity on common AD ports (SMB 445, LDAP 389, LDAPS 636, Kerberos 88)."""
    if not dc_ip:
        return False
    ports = [port, 389, 636, 88]
    for p in ports:
        try:
            with socket.create_connection((str(dc_ip), int(p)), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            continue
    return False


def discover_ad_domain(dc_ip: str, timeout: float = 3.0) -> tuple[str, str]:
    """
    Discovers the Active Directory DNS domain and NetBIOS domain from the DC IP
    using anonymous RootDSE query over LDAP (port 389) or NTLMSSP probe over SMB (port 445).
    """
    import ldap3

    dns_domain = ""
    netbios_domain = ""

    # Method 1: LDAP RootDSE query on port 389 (anonymous)
    try:
        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=timeout)
        conn = ldap3.Connection(server, auto_bind=False)
        conn.open()
        if server.info and server.info.other:
            naming_context = server.info.other.get('defaultNamingContext') or server.info.other.get('rootDomainNamingContext')
            if naming_context:
                nc_str = naming_context[0] if isinstance(naming_context, list) else str(naming_context)
                parts = [part.split('=', 1)[1] for part in nc_str.split(',') if part.strip().upper().startswith('DC=')]
                if parts:
                    dns_domain = ".".join(parts).upper()
                    netbios_domain = parts[0].upper()

            if not dns_domain:
                dns_host = server.info.other.get('dnsHostName')
                if dns_host:
                    host_str = dns_host[0] if isinstance(dns_host, list) else str(dns_host)
                    if '.' in host_str:
                        dns_domain = host_str.split('.', 1)[1].upper()
                        netbios_domain = dns_domain.split('.')[0]
        conn.unbind()
    except Exception:
        pass

    # Method 2: NTLMSSP Challenge over SMB (port 445)
    if not dns_domain:
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(dc_ip, dc_ip, timeout=int(timeout))
            dns_domain = (smb.getServerDNSDomainName() or "").upper()
            netbios_domain = (smb.getServerDomain() or (dns_domain.split('.')[0] if dns_domain else "")).upper()
        except Exception:
            pass

    return dns_domain, netbios_domain


def verify_target_foothold(dc_ip: str, user: str, password: str, domain: str = "", timeout: float = 3.5) -> tuple[bool, str, str]:
    """
    Attempts DC connectivity first, discovers AD domain, and tests LDAP/LDAPS authentication.
    Returns (success, reason_code, message):
      - If DC is unreachable: (False, "dc_unreachable", "Foothold verification failed: DC unreachable")
      - If bind fails: (False, "invalid_credentials", "Foothold verification failed: Invalid credentials")
      - If bind succeeds: (True, "success", f"Successfully bound with foothold account '{user}'.")
    """
    import ldap3

    # Step 1: Ping DC first
    if not ping_target_dc(dc_ip, timeout=timeout):
        return False, "dc_unreachable", "Foothold verification failed: DC unreachable"

    # Step 2: Discover domain from DC if not explicitly provided
    discovered_dns, discovered_netbios = "", ""
    if not domain or not domain.strip():
        discovered_dns, discovered_netbios = discover_ad_domain(dc_ip, timeout=timeout)
        domain = discovered_dns or ""

    candidates = []
    raw = (user or "").strip()
    if raw:
        candidates.append(raw)
        if "\\" in raw:
            parts = raw.split("\\", 1)
            candidates.append(parts[1])
        elif "@" in raw:
            parts = raw.split("@", 1)
            candidates.append(parts[0])

    clean_u = raw.split("\\")[-1].split("@")[0].strip() if raw else ""
    if clean_u:
        if domain:
            candidates.append(f"{clean_u}@{domain}")
            netbios = discovered_netbios or (domain.split(".")[0] if "." in domain else domain)
            if netbios:
                candidates.append(f"{netbios}\\{clean_u}")
        if discovered_netbios:
            candidates.append(f"{discovered_netbios}\\{clean_u}")
        if clean_u not in candidates:
            candidates.append(clean_u)

    unique_candidates = list(dict.fromkeys(candidates))

    # Step 3: Try LDAPS (636) and plain LDAP (389)
    servers = [
        ldap3.Server(dc_ip, port=636, use_ssl=True, connect_timeout=timeout, get_info=None),
        ldap3.Server(dc_ip, port=389, use_ssl=False, connect_timeout=timeout, get_info=None),
    ]

    for server in servers:
        for candidate in unique_candidates:
            try:
                conn = ldap3.Connection(server, user=candidate, password=password, auto_bind=True, raise_exceptions=True)
                if conn.bound:
                    conn.unbind()
                    return True, "success", f"Successfully bound with foothold account '{clean_u}'."
            except Exception:
                continue

    return False, "invalid_credentials", "Foothold verification failed: Invalid credentials"


@router.post("/test/ping")
def test_dc_ping(request: TestPingRequest):
    """Test TCP connectivity to the specified Domain Controller."""
    dc_ip = request.dc_ip.strip()
    success = ping_target_dc(dc_ip, port=request.port, timeout=3.0)
    if success:
        logger.info(
            "SYSTEM", "project.dc_ping.success",
            f"Pre-flight ping check succeeded for DC {dc_ip}",
            source="web.app",
            details={"dc_ip": dc_ip},
        )
        return {
            "status": "ok",
            "reachable": True,
            "message": "Successfully connected to Domain Controller.",
        }
    else:
        logger.warning(
            "SYSTEM", "project.dc_ping.failed",
            f"Pre-flight ping check failed for DC {dc_ip}",
            source="web.app",
            details={"dc_ip": dc_ip},
        )
        return {
            "status": "error",
            "reachable": False,
            "message": "Failed to connect: DC unreachable",
        }


@router.post("/test/foothold")
def test_foothold_credentials(request: TestFootholdRequest):
    """Test LDAP authentication and bind for the specified foothold account on the target DC."""
    dc_ip = request.dc_ip.strip()
    user = request.foothold_username.strip()
    password = request.foothold_password
    domain = request.domain.strip() if request.domain else ""

    success, code, msg = verify_target_foothold(dc_ip, user, password, domain=domain, timeout=4.0)
    if success:
        logger.info(
            "AUTH", "project.foothold_test.success",
            f"Pre-flight foothold authentication succeeded for user '{user}' on DC {dc_ip}",
            source="web.app",
            details={"dc_ip": dc_ip, "username": user},
        )
        return {
            "status": "ok",
            "authenticated": True,
            "message": msg,
        }
    else:
        logger.warning(
            "AUTH", "project.foothold_test.failed",
            f"Pre-flight foothold authentication failed for user '{user}' on DC {dc_ip} [{code}]: {msg}",
            source="web.app",
            details={"dc_ip": dc_ip, "username": user, "code": code},
        )
        return {
            "status": "error",
            "authenticated": False,
            "message": msg,
        }


@router.get("")
def list_projects(include_deleted: bool = Query(False)):
    project_mgr = ProjectManager()
    return {
        "status": "ok",
        "active_project_id": project_mgr.get_active_project_id(),
        "projects": project_mgr.list_projects(include_deleted=include_deleted),
    }


@router.post("/select")
def select_project(request: SelectProjectRequest, req: Request):
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    success = project_mgr.set_active_project(request.project_id)
    if not success:
        logger.warning(
            "PROJECT", "project.select.failed",
            f"Attempted to select non-existent project: {request.project_id}",
            project_id=request.project_id,
            source="web.app",
        )
        raise HTTPException(status_code=404, detail="Project not found")

    logger.info(
        "PROJECT", "project.selected",
        f"Active project switched to: {request.project_id}",
        project_id=request.project_id,
        source="web.app",
    )

    runtime = build_runtime_state(settings)
    return {
        "status": "ok",
        "active_project_id": request.project_id,
        "project": project_mgr.get_project(request.project_id),
        "snapshot": runtime["snapshot"],
        "redirect_url": "/workspace",
    }


@router.post("/create")
def create_project(request: CreateProjectRequest, req: Request):
    valid, result = validate_project_name(request.name)
    if not valid:
        logger.warning(
            "PROJECT", "project.create.invalid_name",
            f"Project creation rejected due to invalid name: {result}",
            source="web.app",
            details={"raw_name": request.name, "error": result},
        )
        raise HTTPException(status_code=400, detail=result)

    cleaned_name = result
    project_mgr = ProjectManager()

    # Duplicate check across ALL projects (both active and soft-deleted)
    if project_mgr.project_name_exists(cleaned_name):
        logger.warning(
            "PROJECT", "project.create.duplicate_name",
            f"Project creation rejected: duplicate name \"{cleaned_name}\" (unique name required across active and archived records)",
            source="web.app",
            details={"name": cleaned_name},
        )
        raise HTTPException(
            status_code=409,
            detail="Project name duplicate. Choose a new name.",
        )

    # Generate a safe, collision-resistant project ID
    project_id = generate_safe_project_id(cleaned_name)

    # Register project with clean initial state and target credentials
    project_entry = project_mgr.register_project(
        project_id=project_id,
        name=cleaned_name,
        dc_ip=request.dc_ip or "",
        foothold_username=request.foothold_username or "",
        foothold_password=request.foothold_password or "",
        source_zip=None,
        nodes=0,
        relationships=0,
    )

    logger.info(
        "PROJECT", "project.created",
        f"Project \"{cleaned_name}\" created successfully (ID: {project_id})",
        project_id=project_id,
        source="web.app",
        details={
            "name": cleaned_name,
            "project_id": project_id,
            "dc_ip": request.dc_ip or "",
            "foothold_username": request.foothold_username or "",
            "has_password": bool(request.foothold_password),
        },
    )

    return {
        "status": "ok",
        "project": project_entry,
        "active_project_id": project_id,
        "redirect_url": "/workspace",
    }


@router.post("/target")
def update_project_target(request: UpdateProjectTargetRequest, req: Request):
    project_mgr = ProjectManager()
    target_project_id = request.project_id or project_mgr.get_active_project_id()
    if not target_project_id:
        raise HTTPException(status_code=400, detail="No active project selected.")

    project = project_mgr.get_project(target_project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    updated = project_mgr.update_project_target(
        project_id=target_project_id,
        dc_ip=request.dc_ip,
        foothold_username=request.foothold_username,
        foothold_password=request.foothold_password,
        domain=request.domain,
    )

    logger.info(
        "PROJECT", "project.target.updated",
        f"Target foothold configuration updated for project '{project.get('name', target_project_id)}'",
        project_id=target_project_id,
        source="web.app",
        details={
            "project_id": target_project_id,
            "dc_ip": updated.get("dc_ip") if updated else "",
            "foothold_username": updated.get("foothold_username") if updated else "",
            "domain": updated.get("domain") if updated else "",
            "has_password": bool(updated.get("foothold_password")) if updated else False,
        },
    )

    return {
        "status": "ok",
        "project": updated,
        "project_id": target_project_id,
    }


@router.delete("/{project_id}")
def delete_project(project_id: str, req: Request):
    settings = req.app.state.settings
    project_mgr = ProjectManager()
    project_info = project_mgr.get_project(project_id)
    project_name = project_info.get("name", project_id) if project_info else project_id

    logger.info(
        "PROJECT", "project.delete.started",
        f"Deleting project \"{project_name}\" ({project_id}) — clearing graph data",
        project_id=project_id,
        source="web.app",
    )

    manager = db_manager(settings)
    try:
        ingestor = SharpHoundIngestor(manager, project_id=project_id)
        ingestor.clear_database(project_id=project_id)
    except Exception as exc:
        logger.error(
            "DATABASE", "project.delete.graph_clear_failed",
            f"Failed to clear graph data for project {project_id}: {exc}",
            project_id=project_id,
            source="web.app",
            details={"error": str(exc)},
        )
        raise
    finally:
        manager.close()

    success = project_mgr.delete_project(project_id)
    if not success:
        logger.warning(
            "PROJECT", "project.delete.registry_failed",
            f"Project {project_id} not found in registry after graph clear",
            project_id=project_id,
            source="web.app",
        )
        raise HTTPException(status_code=404, detail="Project not found in registry")

    logger.info(
        "PROJECT", "project.deleted",
        f"Project \"{project_name}\" ({project_id}) deleted — graph data and registry entry removed",
        project_id=project_id,
        source="web.app",
        details={"project_name": project_name},
    )

    runtime = build_runtime_state(settings)
    return {
        "status": "ok",
        "deleted_project_id": project_id,
        "active_project_id": runtime["active_project_id"],
        "snapshot": runtime["snapshot"],
    }


@router.post("/unlock")
def unlock_project_phase(request: UnlockPhaseRequest, req: Request):
    """Updates the unlocked phase progression for the active or specified project."""
    project_mgr = ProjectManager()
    target_id = request.project_id or project_mgr.get_active_project_id()
    if not target_id:
        raise HTTPException(status_code=400, detail="No active project selected")

    updated = project_mgr.update_project_phase(target_id, request.phase)
    if not updated:
        raise HTTPException(status_code=404, detail="Project not found or invalid phase")

    logger.info(
        "PROJECT", "project.phase_unlocked",
        f"Project {target_id} unlocked to phase: {request.phase}",
        project_id=target_id,
        source="web.app",
        details={"phase": request.phase},
    )

    return {
        "status": "ok",
        "project_id": target_id,
        "unlocked_phase": request.phase,
        "project": updated,
    }


@router.post("/path/save")
def save_project_path(request: SavePathRequest, req: Request):
    """Saves the user-selected path, engine, source, target, and optionally unlocks subsequent phases."""
    project_mgr = ProjectManager()
    target_id = request.project_id or project_mgr.get_active_project_id()
    if not target_id:
        raise HTTPException(status_code=400, detail="No active project selected")

    updated = project_mgr.update_project_path(
        project_id=target_id,
        engine=request.engine,
        path_data=request.path,
        source_name=request.source_name,
        target_name=request.target_name,
        unlock_phase=request.unlock_phase,
        candidate_paths=request.candidate_paths,
        selected_path_index=request.selected_path_index,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Project not found")

    logger.info(
        "PATHFINDER", "pathfinder.path_committed",
        f"Committed path for project {target_id} [{request.engine}]: {request.source_name} → {request.target_name}",
        project_id=target_id,
        source="web.app",
        details={
            "engine": request.engine,
            "source": request.source_name,
            "target": request.target_name,
            "unlocked_phase": updated.get("unlocked_phase"),
        },
    )

    return {
        "status": "ok",
        "project_id": target_id,
        "project": updated,
    }


@router.post("/phase/active")
def set_active_phase(request: SetActivePhaseRequest, req: Request):
    """Updates the last worked-on active phase for the project."""
    project_mgr = ProjectManager()
    target_id = request.project_id or project_mgr.get_active_project_id()
    if not target_id:
        raise HTTPException(status_code=400, detail="No active project selected")

    updated = project_mgr.update_last_active_phase(target_id, request.phase)
    if not updated:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "ok",
        "project_id": target_id,
        "last_active_phase": request.phase,
        "project": updated,
    }


