#!/usr/bin/env python3
"""
ViperACL Environment Purge & Reset Utility

Restores the entire ViperACL repository and database to its pristine initial download state:
1. Neo4j Graph Database: Detaches and deletes all nodes and relationships.
2. Projects Registry & Folders: Wipes all project directories, staging archives, and resets projects.json.
3. Audit & Application Logs: Clears session audit trail (viperacl_audit.jsonl) and stray log files.
4. Generated Remediation Scripts: Removes all generated .ps1 script outputs.
5. Session Artifacts & Settings: Removes extracted session hashes, .kirbi tickets, and resets settings.json.
6. Bytecode & Cache: Cleans __pycache__ and .pytest_cache directories.
7. Asset Integrity Verification: Confirms essential base assets (SharpHound.exe, synthetic datasets, ML models) remain intact.

Usage:
    ./venv/bin/python scripts/purge.py [--yes]
"""

import argparse
import json
import os
import shutil
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
        print(f"    [+] Cleared {nodes_before} nodes and {rels_before} relationships from '{settings.neo4j_database}'.")
        return nodes_before, rels_before
    except Exception as exc:
        print(f"    [!] Error clearing Neo4j database: {exc}")
        return 0, 0
    finally:
        db.close()


def purge_projects() -> int:
    """Removes data/projects/projects.json and all project workspace folders."""
    print("\n[*] 2. Resetting Projects Registry & Workspace Storage...")
    projects_dir = PROJECT_ROOT / "data" / "projects"
    projects_file = projects_dir / "projects.json"
    cleared_count = 0

    if projects_file.exists():
        try:
            data = json.loads(projects_file.read_text(encoding="utf-8"))
            cleared_count = len(data.get("projects", {}))
        except Exception:
            cleared_count = 0
        try:
            projects_file.unlink()
            print(f"    [+] Removed projects.json (purged {cleared_count} registered records).")
        except OSError as exc:
            print(f"    [!] Failed to remove projects.json: {exc}")

    # Remove all project subdirectories (proj_*, storage/, archives/, etc.)
    deleted_dirs = 0
    if projects_dir.exists():
        for item in projects_dir.iterdir():
            if item.is_dir():
                try:
                    shutil.rmtree(item)
                    deleted_dirs += 1
                except Exception as exc:
                    print(f"    [!] Failed to remove project directory {item.name}: {exc}")
            elif item.suffix in [".tmp", ".bak", ".zip"] or item.name.endswith(".json.tmp"):
                try:
                    item.unlink()
                except OSError:
                    pass

    # Ensure .gitkeep exists
    projects_dir.mkdir(parents=True, exist_ok=True)
    gitkeep = projects_dir / ".gitkeep"
    if not gitkeep.exists():
        gitkeep.write_text("# Keep data/projects directory in git\n", encoding="utf-8")

    print(f"    [+] Cleaned {deleted_dirs} project workspace directories.")
    return cleared_count


def purge_logs() -> int:
    """Deletes all session and audit log files in data/logs/."""
    print("\n[*] 3. Clearing Application & Forensic Audit Logs...")
    logs_dir = PROJECT_ROOT / "data" / "logs"
    cleared_files = 0
    if logs_dir.exists():
        for log_file in logs_dir.glob("*"):
            if log_file.is_file() and log_file.name != ".gitkeep":
                try:
                    log_file.unlink()
                    cleared_files += 1
                    print(f"    [+] Removed log file: {log_file.name}")
                except Exception as exc:
                    print(f"    [!] Failed to remove {log_file.name}: {exc}")
    else:
        logs_dir.mkdir(parents=True, exist_ok=True)

    gitkeep = logs_dir / ".gitkeep"
    if not gitkeep.exists():
        gitkeep.write_text("# Keep data/logs directory in git\n", encoding="utf-8")

    print(f"    [+] Log directory reset to pristine state ({cleared_files} files cleaned).")
    return cleared_files


def purge_generated_scripts() -> int:
    """Removes generated remediation scripts from project storage and temporary directories."""
    print("\n[*] 4. Cleaning Generated Remediation Scripts...")
    script_dirs = [
        PROJECT_ROOT / "data" / "projects" / "storage",
        PROJECT_ROOT / "outputs",
    ]
    deleted_scripts = 0
    for s_dir in script_dirs:
        if s_dir.exists():
            for s_file in s_dir.rglob("*.ps1"):
                try:
                    s_file.unlink()
                    deleted_scripts += 1
                except Exception:
                    pass

    # Clean legacy data/scripts if present
    legacy_scripts_dir = PROJECT_ROOT / "data" / "scripts"
    if legacy_scripts_dir.exists():
        try:
            shutil.rmtree(legacy_scripts_dir)
        except Exception:
            pass

    print(f"    [+] Removed {deleted_scripts} generated remediation script(s).")
    return deleted_scripts


def purge_session_artifacts() -> int:
    """Removes session hash dumps, tickets, and resets runtime settings."""
    print("\n[*] 5. Removing Session Attack Artifacts & Settings...")
    data_dir = PROJECT_ROOT / "data"
    removed_items = 0

    # 1. Extracted hashes and Kerberos tickets
    for artifact_name in ["extracted_hashes.txt", "extracted_hashes.txt.tmp"]:
        target = data_dir / artifact_name
        if target.exists():
            try:
                target.unlink()
                removed_items += 1
                print(f"    [+] Removed {target.name}")
            except OSError:
                pass

    for kirbi in data_dir.glob("*.kirbi"):
        try:
            kirbi.unlink()
            removed_items += 1
            print(f"    [+] Removed {kirbi.name}")
        except OSError:
            pass

    # 2. Reset settings.json
    settings_file = data_dir / "settings.json"
    if settings_file.exists():
        try:
            settings_file.unlink()
            removed_items += 1
            print(f"    [+] Removed {settings_file.name} (will regenerate defaults on boot)")
        except OSError:
            pass

    for tmp_file in data_dir.glob("*.tmp"):
        try:
            tmp_file.unlink()
            removed_items += 1
        except OSError:
            pass

    # 3. Clean temporary scratch files if present
    scratch_dir = PROJECT_ROOT / "scratch"
    if scratch_dir.exists():
        for s_item in scratch_dir.iterdir():
            if s_item.is_file() and s_item.name != ".gitkeep":
                try:
                    s_item.unlink()
                    removed_items += 1
                except OSError:
                    pass

    print(f"    [+] Cleaned {removed_items} session artifact(s).")
    return removed_items


def purge_caches() -> int:
    """Cleans Python bytecode and pytest caches."""
    print("\n[*] 6. Cleaning Python Bytecode & Test Caches...")
    removed_caches = 0
    for root, dirs, _ in os.walk(PROJECT_ROOT):
        for d in list(dirs):
            if d == "__pycache__" or d == ".pytest_cache":
                full_path = Path(root) / d
                try:
                    shutil.rmtree(full_path)
                    dirs.remove(d)
                    removed_caches += 1
                except Exception:
                    pass
    print(f"    [+] Removed {removed_caches} cache directories.")
    return removed_caches


def verify_preserved_assets():
    """Confirms essential base tools, datasets, and models are intact."""
    print("\n[*] 7. Verifying Essential Base Repository Assets...")
    essential_assets = [
        ("SharpHound Collector", PROJECT_ROOT / "data" / "tools" / "SharpHound.exe"),
        ("RF Training Dataset", PROJECT_ROOT / "data" / "rf_synthetic_training.csv"),
        ("LGBM Training Dataset", PROJECT_ROOT / "data" / "lgbm_synthetic_training.csv"),
        ("Transformer Sequence Dataset", PROJECT_ROOT / "data" / "transformer_synthetic_training.jsonl"),
        ("Random Forest Model", PROJECT_ROOT / "models" / "rf_viper_model.pkl"),
        ("LightGBM Model", PROJECT_ROOT / "models" / "lgbm_viper_model.pkl"),
        ("Path-Transformer Model", PROJECT_ROOT / "models" / "transformer_viper_model.pt"),
    ]

    all_intact = True
    for label, path in essential_assets:
        if path.exists() and path.stat().st_size > 0:
            print(f"    [✓] {label:32}: Present ({path.stat().st_size:,} bytes)")
        else:
            print(f"    [!] {label:32}: MISSING ({path})")
            all_intact = False

    return all_intact


def main():
    parser = argparse.ArgumentParser(
        description="Reset ViperACL repository and database to initial pristine download state."
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    print("=" * 70)
    print("        VIPERACL INITIAL DOWNLOAD STATE RESTORATION UTILITY")
    print("=" * 70)
    print("WARNING: This will permanently wipe:")
    print("  - All Neo4j graph nodes and relationships")
    print("  - All project records, workspaces, and staging archives")
    print("  - All audit logs and session logs")
    print("  - All generated remediation scripts")
    print("  - All session hashes, .kirbi files, and local settings.json")
    print("  - All __pycache__ and test caches")
    print("=" * 70)

    if not args.yes:
        confirm = input("\nRestore workspace to pristine download state? [y/N]: ").strip().lower()
        if confirm not in ["y", "yes"]:
            print("\n[-] Purge aborted by user.")
            sys.exit(0)

    settings = load_settings()
    purge_neo4j(settings)
    purge_projects()
    purge_logs()
    purge_generated_scripts()
    purge_session_artifacts()
    purge_caches()
    intact = verify_preserved_assets()

    print("\n" + "=" * 70)
    if intact:
        print("[✓] ViperACL workspace successfully restored to initial download state.")
    else:
        print("[!] Reset complete, but some essential base assets were not found.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
