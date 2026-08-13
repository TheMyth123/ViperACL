# ViperACL Web Application Plan & Roadmap

## 1. Completed Implementation (Page by Page)

### A. Global Landing Page (`/`)
- **Single-Page Design Layout**: Built a fixed, responsive 1-page dashboard layout optimized for standard laptop dimensions without vertical scrollbars.
- **System Health Status Indicator**:
  - `Active` (Neo4j Connected & Random Forest ML Model Ready)
  - `Degraded (No ML)` (Neo4j Connected, ML Model Offline)
  - `Offline (No DB)` (Neo4j Database Disconnected)
  - Includes bracketed troubleshooting helper text for rapid error diagnosis.
- **Global Database Status Card**:
  - Always displays the total combined inventory of nodes (584) and relationships (3,867) across all ingested project graphs in Neo4j.
- **Projects Archive Accordion Drawer**:
  - Native HTML5 `<details>` & `<summary>` accordion drawer on the left sidebar.
  - Smooth expansion pushing down Global Logs & Settings links without JS interference.
  - Lists saved projects from `projects/projects.json` with node/relationship metrics and dedicated trash icon deletion buttons (`deleteProject`).
  - Project entry cards act as entry points to the upcoming Project Dashboard.
- **IDE-Style Settings Popup Window**:
  - **Database Connection Tab**: Configurable Bolt URI (`bolt://127.0.0.1:7687`), Username (`neo4j`), Password (`viperacl`), Database Name (`neo4j`), and live **Test Connection** button (`POST /api/neo4j/test`).
  - **Engine & ML Preferences Tab**: Default pathfinding mode (Tactical, FastTrack, Predictive), max hops limit, and ML confidence threshold.
  - **Remediation Settings Tab**: PowerShell export directory (`scripts/`) and fixed script format statement (`Active Directory PowerShell Script (.ps1)`).
  - **Micro-Animations**: Smooth 200ms scale-up (`scale-95` ➔ `scale-100`) and fade-in modal entrance/exit transitions.

### B. Multi-Project Engine & Database Layer
- **Project Metadata Registry** (`core/projects.py` & `projects/projects.json`): Manages project definitions, timestamps, and node/edge metrics.
- **Neo4j Graph Isolation** (`core/ingestor/parser.py` & `utils/database.py`):
  - Ingests SharpHound datasets with project-scoped properties (`n.project_id`, `r.project_id`).
  - Supports project-isolated database clearing (`clear_database(project_id)`).
- **Multi-Project Ingestion Testing** (`dev/test_ingest.py`): Ingests multiple SharpHound archives into separate isolated subgraphs within the same Neo4j instance.

---

## 2. Upcoming Features & Roadmap (To Be Built Next)

### 1. Global Logs Page / Modal
- **Purpose**: A centralized system log viewer accessible via the left sidebar **Global Logs** button.
- **Key Capabilities**:
  - Real-time streaming log display.
  - Log feeds for Web Server access/error logs (`/tmp/viperacl.log`), Neo4j container stdout, ingestion parser events, and background tasks.
  - Log filtering by severity (INFO, WARNING, ERROR).

### 2. Project Dashboard Page
- **Purpose**: Dedicated workspace interface launched when a user clicks a project in the Projects Archive drawer.
- **Key Capabilities**:
  - **Header & Scope**: Displays current active project context, domain name, and project-isolated graph metrics.
  - **Four-Phase Workflow Suite**:
    1. **Ingest Phase**: Upload/re-ingest SharpHound archives scoped to the project.
    2. **Pathfinder Phase**: Run shortest-path or predictive Random Forest attack path analysis between source principals and target domain assets.
    3. **Privesc Execution Phase**: Generate actionable privilege escalation steps and validation tasks.
    4. **Remediation Phase**: Generate tailored PowerShell remediation scripts (`.ps1`) to remove vulnerable ACL permissions (`Remove-ADPermission`).

### 3. Interactive Graph Visualizer
- **Purpose**: Visual graph canvas (e.g. Vis.js or Cytoscape.js) to render attack paths, choke points, and compromised AD objects interactively within the Project Dashboard.
