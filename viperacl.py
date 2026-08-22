import argparse
import subprocess
import socket
import sys
import time
from pathlib import Path

import uvicorn

from core.database import DatabaseManager
from web.app import create_app
from web.config import load_settings


PROJECT_ROOT = Path(__file__).resolve().parent


def find_free_port(host):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def initialize_environment():
    """Initializes and verifies necessary session storage, registry, and audit files on startup."""
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Initializing ViperACL workspace storage and session files...")

    # 1. Configuration: data/settings.json
    settings_file = data_dir / "settings.json"
    if not settings_file.exists():
        load_settings()
        print("    [+] Created data/settings.json (configuration loaded with default policy)")
    else:
        print("    [*] Loaded data/settings.json")

    # 2. Projects Registry: data/projects/projects.json
    projects_file = data_dir / "projects" / "projects.json"
    is_new_projects = not projects_file.exists()
    from core.projects import ProjectManager
    pm = ProjectManager()
    if is_new_projects:
        print("    [+] Created data/projects/projects.json (project registry initialized)")
    else:
        active_count = len(pm.list_projects())
        print(f"    [*] Loaded data/projects/projects.json ({active_count} active projects registered)")

    # 3. Forensic Audit Logs: data/logs/viperacl_audit.jsonl
    audit_file = data_dir / "logs" / "viperacl_audit.jsonl"
    is_new_audit = not audit_file.exists()
    from core.logger import logger
    logger.info("SYSTEM", "system.startup", "ViperACL web application startup initiated", source="app.cli")
    if is_new_audit:
        print("    [+] Created data/logs/viperacl_audit.jsonl (audit trail initialized)")
    else:
        print("    [*] Loaded data/logs/viperacl_audit.jsonl (audit trail active)")


def start_local_neo4j():
    """Ensures the local Neo4j container is running across Docker Compose V2, V1, and direct Docker environments."""
    print("[*] Ensuring local Neo4j container is running...")

    # Method 1: Docker Compose V2 CLI Plugin ('docker compose')
    res_v2 = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if res_v2.returncode == 0:
        up_res = subprocess.run(
            ["docker", "compose", "up", "-d", "neo4j"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
        )
        if up_res.returncode == 0:
            return

    # Method 2: Standalone Docker Compose ('docker-compose')
    res_v1 = subprocess.run(["docker-compose", "version"], capture_output=True, text=True)
    if res_v1.returncode == 0 and "Docker Compose" in (res_v1.stdout + res_v1.stderr):
        up_res = subprocess.run(
            ["docker-compose", "up", "-d", "neo4j"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
        )
        if up_res.returncode == 0:
            return

    # Method 3: Direct Docker Engine fallback ('docker start' / 'docker run')
    # Guarantees startup even on minimal setups without docker-compose or docker-compose-v2
    inspect_res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", "viperacl-neo4j"],
        capture_output=True,
        text=True,
    )
    if inspect_res.returncode == 0:
        if inspect_res.stdout.strip().lower() == "true":
            return
        start_res = subprocess.run(["docker", "start", "viperacl-neo4j"], capture_output=True, text=True)
        if start_res.returncode == 0:
            return

    run_cmd = [
        "docker", "run", "-d",
        "--name", "viperacl-neo4j",
        "--restart", "unless-stopped",
        "-p", "7474:7474",
        "-p", "7687:7687",
        "-e", "NEO4J_AUTH=neo4j/viperacl",
        "-e", "NEO4J_server_memory_heap_initial__size=512m",
        "-e", "NEO4J_server_memory_heap_max__size=1G",
        "-e", "NEO4J_server_memory_pagecache_size=512m",
        "-v", "neo4j_data:/data",
        "-v", "neo4j_logs:/logs",
        "-v", "neo4j_import:/import",
        "-v", "neo4j_plugins:/plugins",
        "neo4j:5.26-community",
    ]
    run_res = subprocess.run(run_cmd, capture_output=True, text=True)
    if run_res.returncode == 0:
        return

    err_msg = (run_res.stderr or run_res.stdout or "").strip() or "Docker daemon is not responding."
    raise RuntimeError(
        f"Failed to start local Neo4j container.\n"
        f"Error details: {err_msg}\n"
        f"Ensure Docker is running (`sudo systemctl start docker` / `sudo apt install docker-compose-v2`), "
        f"or pass --no-bootstrap-db to use an external Neo4j instance."
    )


def wait_for_neo4j(settings, timeout_seconds=60):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        manager = DatabaseManager(
            uri=settings.neo4j_uri,
            username=settings.neo4j_username,
            password=settings.neo4j_password,
            database=settings.neo4j_database,
        )
        try:
            if manager.connect():
                manager.close()
                return True
        finally:
            manager.close()

        time.sleep(2)

    return False


def main():
    initialize_environment()
    settings = load_settings()

    parser = argparse.ArgumentParser(description="Start the ViperACL web app.")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--no-bootstrap-db", action="store_true", help="Skip starting the local Neo4j container.")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development.")
    args = parser.parse_args()

    if not args.no_bootstrap_db:
        start_local_neo4j()
        if not wait_for_neo4j(settings):
            print("[!] Neo4j did not become ready in time.")
            sys.exit(1)

    port = args.port or find_free_port(args.host)

    print(f"[*] ViperACL web app starting on http://{args.host}:{port}")
    print(f"[*] Neo4j target: {settings.neo4j_uri} ({settings.neo4j_database})")

    if args.reload:
        uvicorn.run(
            "web.app:create_app",
            host=args.host,
            port=port,
            log_level="info",
            factory=True,
            reload=True,
            timeout_graceful_shutdown=2,
        )
    else:
        app = create_app()
        uvicorn.run(
            app,
            host=args.host,
            port=port,
            log_level="info",
            timeout_graceful_shutdown=2,
        )


if __name__ == "__main__":
    main()
