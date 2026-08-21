#!/usr/bin/env python3
"""
ViperACL Development Environment Purge Script

Resets the entire development and test environment to a pristine initial state:
- Clears all nodes and relationships in the Neo4j graph database.
- Resets data/projects/projects.json to empty state.
- Clears audit and application logs in logs/.
- Cleans generated scripts in data/scripts/ and scripts/.

Usage:
    python3 dev/purge.py [--yes]
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.database import DatabaseManager
from web.config import load_settings


def purge_neo4j(settings) -> tuple[int, int]:
    """Clears all nodes and relationships from the Neo4j database."""
    print("\n[*] 1. Purging Neo4j Graph Database...")
    db = DatabaseManager(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        if not db.connect():
            print("    [!] Warning: Could not connect to Neo4j. Skipping graph purge.")
            return 0, 0

        node_res = db.run_query("MATCH (n) RETURN count(n) AS count")
        rel_res = db.run_query("MATCH ()-[r]->() RETURN count(r) AS count")
        nodes_before = node_res[0]["count"] if node_res else 0
        rels_before = rel_res[0]["count"] if rel_res else 0

        db.run_query("MATCH (n) DETACH DELETE n")
        print(f"    [+] Cleared {nodes_before} nodes and {rels_before} relationships from {settings.neo4j_database}.")
        return nodes_before, rels_before
    except Exception as exc:
        print(f"    [!] Error clearing Neo4j database: {exc}")
        return 0, 0
    finally:
        db.close()


def purge_projects() -> int:
    """Resets data/projects/projects.json to an empty state."""
    print("\n[*] 2. Resetting Projects Registry...")
    projects_file = PROJECT_ROOT / "data" / "projects" / "projects.json"
    cleared_count = 0
    if projects_file.exists():
        try:
            data = json.loads(projects_file.read_text(encoding="utf-8"))
            cleared_count = len(data.get("projects", {}))
        except Exception:
            cleared_count = 0

    clean_state = {
        "active_project_id": None,
        "projects": {}
    }
    projects_file.parent.mkdir(parents=True, exist_ok=True)
    projects_file.write_text(json.dumps(clean_state, indent=2), encoding="utf-8")

    # Remove any stray temporary files in data/projects
    for tmp_file in projects_file.parent.glob("*.tmp"):
        try:
            tmp_file.unlink()
        except OSError:
            pass

    print(f"    [+] Reset {projects_file.name} (purged {cleared_count} registered project records).")
    return cleared_count


def purge_logs() -> int:
    """Clears all log files in logs/ directory."""
    print("\n[*] 3. Clearing Application & Audit Logs...")
    logs_dir = PROJECT_ROOT / "data" / "logs" 
    cleared_files = 0
    if logs_dir.exists():
        for log_file in logs_dir.glob("*"):
            if log_file.is_file() and log_file.suffix in [".log", ".jsonl", ".txt"]:
                try:
                    log_file.write_text("", encoding="utf-8")
                    cleared_files += 1
                    print(f"    [+] Emptied log file: {log_file.name}")
                except Exception as exc:
                    print(f"    [!] Failed to clear {log_file.name}: {exc}")
    else:
        logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"    [+] Cleared {cleared_files} log files.")
    return cleared_files


def purge_generated_scripts() -> int:
    """Removes generated remediation scripts."""
    print("\n[*] 4. Cleaning Generated Script Outputs...")
    script_dirs = [
        PROJECT_ROOT / "data" / "scripts",
        PROJECT_ROOT / "scripts",
        PROJECT_ROOT / "outputs",
    ]
    deleted_scripts = 0
    for s_dir in script_dirs:
        if s_dir.exists():
            for s_file in s_dir.glob("*.ps1"):
                try:
                    s_file.unlink()
                    deleted_scripts += 1
                except Exception:
                    pass
    print(f"    [+] Removed {deleted_scripts} generated script file(s).")
    return deleted_scripts


def main():
    parser = argparse.ArgumentParser(description="Purge ViperACL dev database, project records, and logs.")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    print("=" * 65)
    print("       VIPERACL DEV ENVIRONMENT PURGE UTILITY")
    print("=" * 65)
    print("WARNING: This will permanently wipe:")
    print("  - All Neo4j graph nodes and relationships")
    print("  - All project records in data/projects/projects.json")
    print("  - All audit logs in logs/")
    print("  - All generated remediation scripts")
    print("=" * 65)

    if not args.yes:
        confirm = input("\nAre you sure you want to proceed with full purge? [y/N]: ").strip().lower()
        if confirm not in ["y", "yes"]:
            print("\n[-] Purge aborted by user.")
            sys.exit(0)

    settings = load_settings()
    purge_neo4j(settings)
    purge_projects()
    purge_logs()
    purge_generated_scripts()

    print("\n" + "=" * 65)
    print("[✓] ViperACL environment successfully restored to pristine state.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
