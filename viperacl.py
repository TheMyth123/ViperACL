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
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    if not compose_file.is_file():
        raise RuntimeError(f"Docker Compose file not found: {compose_file}")

    print("[*] Ensuring local Neo4j container is running...")
    commands = [
        ["docker", "compose", "up", "-d", "neo4j"],
        ["docker-compose", "up", "-d", "neo4j"],
    ]

    last_error = None
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return
            last_error = (result.stderr or result.stdout or "").strip()
        except FileNotFoundError:
            continue
        except Exception as e:
            last_error = str(e)

    raise RuntimeError(
        f"Failed to start local Neo4j container via Docker Compose.\n"
        f"Error details: {last_error if last_error else 'docker / docker-compose command not found'}\n"
        f"Please verify Docker is running, or pass --no-bootstrap-db to use an external Neo4j instance."
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
