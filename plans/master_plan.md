# ViperACL Master Blueprint

## Project Overview
ViperACL is a red‑team / pentest utility that ingests SharpHound data, discovers mis‑configured ACLs in Active Directory, and generates PowerShell remediation scripts. The solution consists of two major phases:

1. **Backend (CLI)** – ingest, path‑finding, and script generation.
2. **Frontend (GUI)** – a lightweight web UI that calls the backend functions.

## Directory Layout
```
ViperACL/
├─ core/                     # Core backend logic
│   ├─ __init__.py
│   ├─ database.py           # Neo4j wrapper
│   ├─ ingestor/
│   │   ├─ __init__.py
│   │   └─ ingest.py          # Extract SharpHound zip & load into Neo4j
│   ├─ pathfinder/
│   │   ├─ __init__.py
│   │   └─ find_paths.py      # BloodHound‑style shortest‑path algorithm
│   ├─ remediation/
│   │   ├─ __init__.py
│   │   └─ generate_ps.py     # Build PowerShell remediation script
│   ├─ cli/
│   │   ├─ __init__.py
│   │   └─ main.py            # CLI entry point, orchestrates workflow
│   └─ task_manager.py       # High‑level orchestration helper
├─ gui/                      # Future GUI (Phase 2)
│   ├─ __init__.py
│   ├─ app.py                # Streamlit / Flask entry point
│   └─ static/               # UI assets
├─ dev/                      # Development & test code
│   ├─ __init__.py
│   ├─ tests/                # Unit / integration tests
│   │   ├─ __init__.py
│   │   ├─ test_connection.py
│   │   ├─ test_path.py
│   │   └─ test_full_chain.py
│   └─ mock_data/            # Sample SharpHound zip files for testing
├─ utils/                    # Shared utilities
│   ├─ __init__.py
│   └─ logger.py
├─ viperacl.py               # Top‑level entry point (calls cli.main)
├─ requirements.txt
└─ .gitignore
```

## Implementation Steps
1. **Create package skeleton** – directories and `__init__.py` files.
2. **Ingestor (`core/ingestor/ingest.py`)** – unzip, parse CSV/JSON, load nodes/edges via `core.database`.
3. **Pathfinder (`core/pathfinder/find_paths.py`)** – implement shortest‑path search between two principals.
4. **Remediation (`core/remediation/generate_ps.py`)** – translate ACL findings into PowerShell `Remove‑ADPermission` commands.
5. **CLI (`core/cli/main.py`)** – argument parsing, sequential execution, logging, error handling.
6. **Task Manager (`core/task_manager.py`)** – helper to run the full pipeline programmatically.
7. **Move existing tests** to `dev/tests/` and update imports accordingly.
8. **Update top‑level `viperacl.py`** to invoke the new CLI.
9. **Prepare GUI stub** (`gui/app.py`) for future development.

**New Abuse Workflow**
- **Confirm/Abuse** – After a path is found, use `core.abuse.confirm.PathConfirmer` to attempt the ACL abuse steps and verify the path is viable.
- **Credential Extraction** – If confirmed, `core.abuse.extract.CredentialExtractor` extracts password hashes or clear‑text credentials from the target.
- **Remediation Generation** – With credentials in hand, generate a PowerShell remediation script via `core.remediation.generate_ps`.

All code will be added as stubs with docstrings and `pass` statements where detailed logic will be filled later.
