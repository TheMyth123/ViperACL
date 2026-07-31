# ViperACL Master Blueprint

## Project Overview
ViperACL is a red‑team / pentest utility that ingests SharpHound data, discovers mis‑configured ACLs in Active Directory, and generates PowerShell remediation scripts. The solution consists of two major phases:

1. **Backend (CLI)** – ingest, path‑finding, and script generation.
2. **Frontend (GUI)** – a lightweight web UI that calls the backend functions.

## Directory Layout

```
ViperACL/
├─ config.yaml               # Database configuration
├─ core/                     # Core backend logic
│   ├─ __init__.py
│   ├─ ingestor/
│   │   └─ __init__.py       # Extract SharpHound zip & load into Neo4j
│   ├─ pathfinder/
│   │   ├─ __init__.py
│   │   └─ pathfinder.py     # Neo4j-backed shortest‑path algorithm
│   ├─ privesc/              # Privilege escalation and exploitation workflow
│   │   ├─ __init__.py
│   │   ├─ exploit.py        
│   │   └─ task_manager.py   # High‑level orchestration helper
│   └─ remediation/
│       └─ __init__.py       # Build PowerShell remediation script
├─ dev/                      # Development & test code
│   ├─ 20260613062313_ILFREIGHT.zip  # Sample SharpHound zip
│   ├─ test_connection.py
│   ├─ test_full_chain.py
│   └─ test_path.py
├─ logs/                     # Application logs
├─ models/                   # Data models / Schemas
├─ outputs/                  # Generated scripts and artifacts
├─ plans/
│   └─ master_plan.md        # Project documentation
├─ utils/                    # Shared utilities
│   ├─ __init__.py
│   ├─ database.py           # Neo4j connection management
│   └─ logger.py             # Logging configuration
├─ viperacl.py               # Top‑level entry point
└─ requirements.txt          # Python dependencies
```

## Implementation Steps
1. **Create package skeleton** – directories and `__init__.py` files.
2. **Ingestor (`core/ingestor/ingest.py`)** – unzip, parse CSV/JSON, load nodes/edges via `core.database`.
3. **Pathfinder (`core/pathfinder/find_paths.py`)** – implement shortest‑path search between two principals.
4. **PrivEsc (`core/privesc/abuse.py`)** - implement ACL abuse steps an dverify the path is viable
5. **Remediation (`core/remediation/generate_ps.py`)** – translate ACL findings into PowerShell `Remove‑ADPermission` commands.
6. **CLI (`core/cli/main.py`)** – argument parsing, sequential execution, logging, error handling.
7. **Task Manager (`core/task_manager.py`)** – helper to run the full pipeline programmatically.
8. **Move existing tests** to `dev/tests/` and update imports accordingly.
9. **Update top‑level `viperacl.py`** to invoke the new CLI.
10. **Prepare GUI stub** (`gui/app.py`) for future development.
