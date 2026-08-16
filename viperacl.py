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


def start_local_neo4j():
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    if not compose_file.is_file():
        raise RuntimeError(f"Docker Compose file not found: {compose_file}")

    command = ["docker", "compose", "-f", str(compose_file), "up", "-d", "neo4j"]
    print("[*] Ensuring local Neo4j container is running...")
    subprocess.run(command, check=True)


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
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Start the ViperACL web app.")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--no-bootstrap-db", action="store_true", help="Skip starting the local Neo4j container.")
    args = parser.parse_args()

    if not args.no_bootstrap_db:
        start_local_neo4j()
        if not wait_for_neo4j(settings):
            print("[!] Neo4j did not become ready in time.")
            sys.exit(1)

    port = args.port or find_free_port(args.host)
    app = create_app()

    print(f"[*] ViperACL web app starting on http://{args.host}:{port}")
    print(f"[*] Neo4j target: {settings.neo4j_uri} ({settings.neo4j_database})")
    uvicorn.run(app, host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()
