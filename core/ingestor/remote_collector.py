"""
core/ingestor/remote_collector.py
Live Remote Active Directory Collection Engine for ViperACL.
Directly connects to target Domain Controllers via LDAP / Impacket to extract AD directory metadata,
generates standard BloodHound JSON / ZIP data, and automatically ingests it into Neo4j graph partitions.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import ldap3
from ldap3 import ALL, ANONYMOUS, Connection, NTLM, SIMPLE, Server
from ldap3.core.exceptions import LDAPException

from core.ingestor.parser import SharpHoundIngestor
from core.logger import logger
from core.projects import ProjectManager

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def dn_to_domain(dn: str) -> str:
    """Converts LDAP distinguishedName (e.g. 'DC=corp,DC=local') to domain name ('corp.local')."""
    if not dn:
        return ""
    parts = [part.strip()[3:] for part in dn.split(",") if part.strip().upper().startswith("DC=")]
    return ".".join(parts)


def check_dc_reachability(
    dc_ip: str,
    ports: tuple[int, ...] = (389, 445, 88, 636, 53),
    timeout: int = 3,
) -> tuple[bool, int, str]:
    """
    Verifies if the target Domain Controller is reachable on standard AD service ports.
    Returns (is_reachable, open_port, message).
    """
    if not dc_ip:
        return False, 0, "No Domain Controller IP or hostname provided."

    clean_ip = dc_ip.strip()
    for port in ports:
        try:
            with socket.create_connection((clean_ip, int(port)), timeout=float(timeout)):
                return True, port, f"Domain Controller '{clean_ip}' is reachable on port {port}."
        except OSError:
            continue

    return False, 0, f"Domain Controller '{clean_ip}' is unreachable. Verify network routing and firewall rules."


def discover_domain_metadata(dc_ip: str, port: int = 389, timeout: int = 4) -> dict[str, Any]:
    """
    Queries LDAP RootDSE on target Domain Controller to automatically discover:
    - Default Domain Name (from defaultNamingContext)
    - Forest Name (from rootDomainNamingContext)
    - DC Hostname / FQDN (from dnsHostName or serverName)
    """
    result = {
        "success": False,
        "dc_ip": dc_ip,
        "domain": "",
        "forest": "",
        "dc_hostname": "",
        "naming_contexts": [],
        "error": "",
    }
    if not dc_ip:
        result["error"] = "No Domain Controller IP provided"
        return result

    # Strictly convert timeout to int to avoid struct.error in socket setsockopt
    int_timeout = int(timeout) if timeout else 4

    try:
        server = Server(dc_ip.strip(), port=int(port), get_info=ALL, connect_timeout=int_timeout)
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True, receive_timeout=int_timeout)
        if server.info and server.info.other:
            other = server.info.other
            default_nc = other.get("defaultNamingContext")
            if default_nc and isinstance(default_nc, list) and default_nc:
                result["domain"] = dn_to_domain(default_nc[0])
            elif isinstance(default_nc, str):
                result["domain"] = dn_to_domain(default_nc)

            root_nc = other.get("rootDomainNamingContext")
            if root_nc and isinstance(root_nc, list) and root_nc:
                result["forest"] = dn_to_domain(root_nc[0])
            elif isinstance(root_nc, str):
                result["forest"] = dn_to_domain(root_nc)

            dns_host = other.get("dnsHostName")
            if dns_host and isinstance(dns_host, list) and dns_host:
                result["dc_hostname"] = dns_host[0]
            elif isinstance(dns_host, str):
                result["dc_hostname"] = dns_host

            # Fallback to serverName (e.g. CN=DC01,CN=Servers,...) if dnsHostName is missing
            if not result["dc_hostname"]:
                srv_name = other.get("serverName")
                srv_str = srv_name[0] if (isinstance(srv_name, list) and srv_name) else (srv_name if isinstance(srv_name, str) else "")
                if srv_str and srv_str.upper().startswith("CN="):
                    host_part = srv_str.split(",")[0][3:]
                    if result["domain"]:
                        result["dc_hostname"] = f"{host_part}.{result['domain']}".lower()
                    else:
                        result["dc_hostname"] = host_part.lower()

            if server.info.naming_contexts:
                result["naming_contexts"] = list(server.info.naming_contexts)

            result["success"] = bool(result["domain"])
            if result["domain"]:
                result["domain"] = result["domain"].upper()
        conn.unbind()
    except Exception as exc:
        result["error"] = str(exc)

    return result


def validate_live_credentials(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    port: int = 389,
    timeout: int = 5,
) -> tuple[bool, str]:
    """
    Validates foothold credentials by attempting an authenticated LDAP bind against target DC.
    Supports DOMAIN\\username, username@domain, or plain username.
    """
    if not dc_ip or not username:
        return False, "DC IP and Username are required."

    int_timeout = int(timeout) if timeout else 5

    # Format user principal
    clean_user = username.strip()
    if "\\" in clean_user:
        user_dn = clean_user
    elif "@" in clean_user:
        user_dn = clean_user
    elif domain:
        user_dn = f"{domain}\\{clean_user}"
    else:
        user_dn = clean_user

    try:
        server = Server(dc_ip.strip(), port=int(port), connect_timeout=int_timeout)
        # Try NTLM authentication first
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM,
            auto_bind=False,
            receive_timeout=int_timeout,
        )
        if conn.bind():
            conn.unbind()
            return True, "LDAP bind successful (NTLM)"

        # Fallback to SIMPLE authentication
        conn_simple = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=False,
            receive_timeout=int_timeout,
        )
        if conn_simple.bind():
            conn_simple.unbind()
            return True, "LDAP bind successful (Simple)"

        desc = conn.result.get("description", "Invalid username or password")
        return False, f"LDAP bind failed: {desc}"
    except LDAPException as exc:
        return False, f"LDAP authentication error: {exc}"
    except Exception as exc:
        return False, f"Connection error: {exc}"


class LiveADCollector:
    """
    Orchestrates remote agentless Active Directory collection from Linux
    using BloodHound.py, generates standardized JSON archives, and loads them into Neo4j.
    """

    def __init__(self, project_id: str, db_manager: Any):
        self.project_id = project_id
        self.db_manager = db_manager
        self.project_mgr = ProjectManager()

    def collect(
        self,
        dc_ip: str,
        domain: str | None = None,
        username: str = "",
        password: str = "",
        collection_method: str = "DCOnly",
        use_ldaps: bool = False,
        workers: int = 10,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> dict[str, Any]:
        """
        Executes remote Active Directory collection with mandatory preflight checks
        and populates the project graph partition.
        """
        def emit_log(level: str, msg: str):
            if progress_callback:
                try:
                    progress_callback(level, msg)
                except Exception:
                    pass
            severity = "INFO" if level in ("INFO", "SUCCESS") else ("WARNING" if level == "WARN" else "ERROR")
            logger.emit(
                level=severity,
                category="INGEST",
                action="ingest.live_collection.progress",
                message=msg,
                project_id=self.project_id,
                source="core.ingestor.remote",
                details={"dc_ip": dc_ip, "domain": domain, "method": collection_method},
            )

        clean_dc = dc_ip.strip() if dc_ip else ""
        if not clean_dc:
            emit_log("ERROR", "Preflight aborted: No Domain Controller IP provided.")
            raise ValueError("Domain Controller IP is required.")

        emit_log("INFO", f"Starting Active Directory live ingestion pipeline for project '{self.project_id}'...")

        # ---------------------------------------------------------------------
        # PREFLIGHT STEP 1: Check DC Reachability
        # ---------------------------------------------------------------------
        emit_log("INFO", f"[1/4] Preflight Check: Verifying connectivity to Domain Controller '{clean_dc}'...")
        is_reachable, open_port, reach_msg = check_dc_reachability(clean_dc, timeout=3)
        if not is_reachable:
            emit_log("ERROR", f"[1/4] DC Reachability Failed: {reach_msg}")
            logger.warning(
                "INGEST", "ingest.preflight.dc_unreachable",
                f"Domain Controller '{clean_dc}' unreachable during live AD collection preflight",
                project_id=self.project_id,
                source="core.ingestor.remote",
                details={"dc_ip": clean_dc},
            )
            raise RuntimeError(f"Domain Controller '{clean_dc}' is unreachable. Verify network connectivity, VPN, or firewall.")

        emit_log("SUCCESS", f"[1/4] DC Online: Connected to '{clean_dc}' on port {open_port}.")

        # ---------------------------------------------------------------------
        # PREFLIGHT STEP 2: Discover Domain & DC FQDN via RootDSE & Validate Domain
        # ---------------------------------------------------------------------
        emit_log("INFO", f"[2/4] Querying Domain Controller LDAP RootDSE for domain metadata and DC hostname...")
        dse_meta = discover_domain_metadata(clean_dc, timeout=4)
        
        discovered_domain = (dse_meta.get("domain") or "").strip().upper()
        target_domain = domain.strip().upper() if domain else ""

        if target_domain and discovered_domain and target_domain != discovered_domain:
            err_msg = (
                f"Domain mismatch error: Target Domain Controller '{clean_dc}' hosts domain '{discovered_domain}', "
                f"but '{target_domain}' was entered. Please verify the domain name or use Auto-Discover."
            )
            emit_log("ERROR", f"[2/4] Domain Validation Failed: Target domain '{target_domain}' does not match the DC domain ('{discovered_domain}').")
            emit_log("ERROR", f"[2/4] Please check the domain name. The DC reported domain: '{discovered_domain}'.")
            raise RuntimeError(err_msg)

        if not target_domain and discovered_domain:
            target_domain = discovered_domain
            emit_log("SUCCESS", f"[2/4] Domain Auto-Discovered: '{target_domain}' (DC Host: {dse_meta.get('dc_hostname', clean_dc)})")
        elif target_domain:
            emit_log("INFO", f"[2/4] Target Domain: '{target_domain}' (DC Host: {dse_meta.get('dc_hostname', clean_dc)})")
        else:
            emit_log("WARN", f"[2/4] RootDSE lookup returned: {dse_meta.get('error') or 'None'}. Falling back to DC IP.")
            target_domain = clean_dc

        # ---------------------------------------------------------------------
        # PREFLIGHT STEP 3: Validate Foothold Credentials
        # ---------------------------------------------------------------------
        clean_user = username.strip() if username else ""
        if clean_user and password is not None:
            emit_log("INFO", f"[3/4] Preflight Check: Validating credentials for user '{clean_user}' against DC '{clean_dc}'...")
            auth_ok, auth_msg = validate_live_credentials(
                clean_dc, target_domain, clean_user, password, timeout=5
            )
            if not auth_ok:
                emit_log("ERROR", f"[3/4] Foothold Credential Check Failed: {auth_msg}")
                logger.warning(
                    "INGEST", "ingest.preflight.auth_failed",
                    f"Foothold authentication failed for user '{clean_user}' on DC '{clean_dc}': {auth_msg}",
                    project_id=self.project_id,
                    source="core.ingestor.remote",
                    details={"dc_ip": clean_dc, "username": clean_user, "domain": target_domain},
                )
                raise RuntimeError(f"Foothold authentication failed for '{clean_user}': {auth_msg}")

            emit_log("SUCCESS", f"[3/4] Foothold Verified: Authenticated successfully as '{clean_user}' via LDAP bind.")
            logger.info(
                "INGEST", "ingest.preflight.auth_success",
                f"Foothold authentication verified for user '{clean_user}' on DC '{clean_dc}'",
                project_id=self.project_id,
                source="core.ingestor.remote",
                details={"dc_ip": clean_dc, "username": clean_user, "domain": target_domain},
            )
        else:
            emit_log("INFO", "[3/4] Anonymous / Unauthenticated enumeration mode (no user credentials supplied).")

        # ---------------------------------------------------------------------
        # STEP 4: Setup isolated staging directory & Execute BloodHound Engine
        # ---------------------------------------------------------------------
        project_dir = self.project_mgr.get_project_dir(self.project_id)
        staging_dir = project_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
        prefix = f"{timestamp_str}_remote_"

        venv_bh = PROJECT_ROOT / "venv" / "bin" / "bloodhound-python"
        bh_executable = str(venv_bh) if venv_bh.exists() else "bloodhound-python"

        # Resolve target DC FQDN vs Nameserver IP
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_dc))
        nameserver = clean_dc if is_ip else ""
        
        dc_hostname = ""
        if is_ip:
            discovered_host = dse_meta.get("dc_hostname", "").strip() if dse_meta else ""
            if discovered_host and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', discovered_host):
                dc_hostname = discovered_host
        else:
            dc_hostname = clean_dc

        cmd = [
            bh_executable,
            "-d", target_domain,
            "-c", "DCOnly",
            "--zip",
            "-op", prefix,
            "--dns-timeout", "3",
            "--auth-method", "ntlm",
        ]

        if dc_hostname:
            cmd.extend(["-dc", dc_hostname])
        if nameserver:
            cmd.extend(["-ns", nameserver])

        if clean_user:
            raw_user = clean_user
            if "\\" in raw_user:
                raw_user = raw_user.split("\\")[-1]
            if "@" in raw_user:
                raw_user = raw_user.split("@")[0]
            cmd.extend(["-u", raw_user])

        if password:
            cmd.extend(["-p", password])

        if use_ldaps:
            cmd.append("--use-ldaps")

        if workers and workers > 0:
            cmd.extend(["-w", str(min(workers, 15))])

        emit_log("INFO", f"[4/4] Executing Active Directory Collection Engine (DCOnly via {dc_hostname or nameserver})...")

        # Set unbuffered environment so stdout lines stream in real time
        proc_env = os.environ.copy()
        proc_env["PYTHONUNBUFFERED"] = "1"

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(staging_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=proc_env,
            )

            stdout_lines = []
            if process.stdout:
                for line in process.stdout:
                    clean_line = line.strip()
                    if clean_line:
                        stdout_lines.append(clean_line)
                        if "WARNING: Failed to get Kerberos TGT" in clean_line or "Getting TGT for user" in clean_line:
                            continue
                        if any(clean_line.startswith(pfx) for pfx in ("Traceback (most recent call last):", "File \"", "sys.exit", "ad.dns_resolve", "q = self.dnsresolver", "return self.resolve", "timeout = self._compute_timeout", "raise LifetimeTimeout", "dns.resolver.LifetimeTimeout:")) or "~~~^" in clean_line or clean_line.startswith("...<"):
                            continue
                        emit_log("INFO", clean_line)

            process.wait(timeout=180)
            if process.returncode != 0:
                combined_out = " ".join(stdout_lines)
                if "LifetimeTimeout" in combined_out or "dns.resolver" in combined_out or "Server Do53" in combined_out or "The DNS operation timed out" in combined_out or "NXDOMAIN" in combined_out:
                    clean_err = f"Domain validation error: DNS query to DC '{clean_dc}:53' for domain '{target_domain}' timed out or failed. Please check the domain name and ensure the DC's DNS service is accessible."
                elif "Invalid credentials" in combined_out or "INVALID_CREDENTIALS" in combined_out or "KDC_ERR_PREAUTH_FAILED" in combined_out:
                    clean_err = f"Authentication failed for user '{clean_user}'. Check the foothold username and password."
                elif "Connection refused" in combined_out or "LDAPSocketOpenError" in combined_out:
                    clean_err = f"Connection error: Could not establish LDAP connection to DC '{clean_dc}'. Verify the DC IP address and network reachability."
                else:
                    non_tb_lines = [l for l in stdout_lines if not l.startswith("File ") and not l.startswith("Traceback") and "~~~" not in l and not l.startswith("sys.exit")]
                    clean_err = f"Active Directory collection failed: {non_tb_lines[-1] if non_tb_lines else f'Exit code {process.returncode}'}"

                emit_log("ERROR", f"[4/4] Collection Engine Error: {clean_err}")
                raise RuntimeError(clean_err)

        except subprocess.TimeoutExpired:
            process.kill()
            emit_log("ERROR", "Collection engine timed out after 180 seconds.")
            raise RuntimeError("Collection engine timed out. Verify network latency and DC responsiveness.")
        except Exception as exc:
            emit_log("ERROR", f"Failed to execute collection: {exc}")
            raise

        # ---------------------------------------------------------------------
        # STEP 5: Locate generated .zip archive
        # ---------------------------------------------------------------------
        generated_zips = sorted(
            staging_dir.glob(f"{prefix}*.zip"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not generated_zips:
            generated_zips = sorted(
                staging_dir.glob("*.zip"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )

        if not generated_zips:
            emit_log("ERROR", "No .zip archive was produced by the collection engine.")
            raise RuntimeError("Collection finished but no .zip archive was found.")

        zip_archive = generated_zips[0]
        emit_log("SUCCESS", f"Collection archive generated: {zip_archive.name} ({zip_archive.stat().st_size / 1024:.1f} KB)")

        # ---------------------------------------------------------------------
        # STEP 6: Ingest into Neo4j Graph Partition (Tagged with project_id)
        # ---------------------------------------------------------------------
        emit_log("INFO", f"Ingesting Active Directory objects into Neo4j graph partition for project '{self.project_id}'...")
        ingestor = SharpHoundIngestor(self.db_manager, project_id=self.project_id)
        ingestor.clear_database(project_id=self.project_id)
        ingestor.ingest_zip(str(zip_archive), project_id=self.project_id)

        # ---------------------------------------------------------------------
        # STEP 7: Query node & relationship counts
        # ---------------------------------------------------------------------
        node_res = self.db_manager.run_query(
            "MATCH (n:Base {project_id: $pid}) RETURN count(n) as node_count",
            {"pid": self.project_id},
        )
        rel_res = self.db_manager.run_query(
            "MATCH ()-[r {project_id: $pid}]->() RETURN count(r) as rel_count",
            {"pid": self.project_id},
        )
        node_count = node_res[0].get("node_count", 0) if node_res else 0
        rel_count = rel_res[0].get("rel_count", 0) if rel_res else 0

        # ---------------------------------------------------------------------
        # STEP 8: Update Project Metadata & Unlock Phase 2 (Pathfinder)
        # ---------------------------------------------------------------------
        if target_domain and target_domain != "UNKNOWN.LOCAL":
            self.project_mgr.update_project_target(self.project_id, domain=target_domain)

        self.project_mgr.reset_project_pipeline_on_reingest(
            self.project_id,
            nodes=node_count,
            relationships=rel_count,
            source_zip=zip_archive.name,
        )

        emit_log(
            "SUCCESS",
            f"Ingestion complete! Successfully loaded {node_count} nodes and {rel_count} relationships. Phase 2 Pathfinder unlocked.",
        )

        logger.info(
            "INGEST",
            "ingest.live_collection.completed",
            f"Live remote AD collection completed for project {self.project_id}: {node_count} nodes, {rel_count} relationships",
            project_id=self.project_id,
            source="core.ingestor.remote",
            details={
                "dc_ip": clean_dc,
                "domain": target_domain,
                "collection_method": "DCOnly",
                "nodes": node_count,
                "relationships": rel_count,
                "archive_name": zip_archive.name,
            },
        )

        return {
            "success": True,
            "project_id": self.project_id,
            "domain": target_domain,
            "nodes": node_count,
            "relationships": rel_count,
            "archive_filename": zip_archive.name,
            "staged_path": str(zip_archive.relative_to(PROJECT_ROOT)),
        }
