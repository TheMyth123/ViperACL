# ViperACL 🛡️🐍

> **Autonomous Active Directory Attack Path Orchestration, Machine Learning Feasibility Scoring, & Surgical Remediation Framework**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-5.26-008CC1.svg?style=flat&logo=neo4j)](https://neo4j.com/)
[![Code Style: Clean & Secure](https://img.shields.io/badge/Security-Zero--Trust-green.svg)](https://github.com/)

---

## 📖 Overview

**ViperACL** is an enterprise-grade Active Directory security framework designed to bridge the gap between static graph theory (e.g., BloodHound Dijkstra shortest paths) and live offensive/defensive operations.

Traditional pathfinding tools evaluate attack paths using static hop counts or fixed cost tables, making them blind to sequential exploit dependencies and operational friction in live Active Directory environments. ViperACL introduces an end-to-end **4-Phase Autonomous Pipeline** powered by a **Machine Learning Predictive Engine** that evaluates real-world execution feasibility, executes surgical privilege escalation steps, and automatically generates production-ready PowerShell remediation scripts.

| Phase | Core Objective | Key Capabilities |
| :--- | :--- | :--- |
| **Phase 1: Ingest & Scope** | Ingestion & Environment Setup | SharpHound ZIP Ingestion, Multi-Project Graph Isolation, DC Reachability & Preflight Checks |
| **Phase 2: Pathfinder** | Multi-Engine Attack Routing | FastTrack (Shortest Hop), Tactical Cost Map, Predictive ML (Combinatorial Blindspot Resolution) |
| **Phase 3: Privesc Execution** | Automated Path Execution | Modular Active Directory Exploits (LDAP / Impacket), Credential Dumps, Real-Time Live Feed |
| **Phase 4: Surgical Remediation** | Hardening & Severance | Idempotent PowerShell Script Builder, 19 AD Edge Mitigations, SACL Owner Restoration |

---

## 🚀 The 4 Operational Phases

### Phase 1: Ingest & Project Isolation
* **High-Speed ZIP Ingestion**: Parses SharpHound JSON output archives (`users.json`, `groups.json`, `computers.json`, `domains.json`, `acls.json`) into Neo4j in seconds using batch-optimized transactions and compound indexes.
* **Project Graph Partitioning**: Strictly isolates target Active Directory environments using dedicated project scopes and separate database workspaces.
* **Pre-flight Connectivity Verification**: Built-in ICMP ping and LDAP bind testing to validate Domain Controller reachability and foothold credentials prior to engagement.

### Phase 2: Intelligent Multi-Engine Attack Pathfinder
ViperACL provides three distinct pathfinding engines tailored for different operational objectives:
1. **Viper FastTrack (Shortest Path)**: Uses Dijkstra's algorithm to compute the absolute lowest hop count to Domain Admin / Domain Root.
2. **Viper Tactical (Operational Cost Map)**: Evaluates edge costs to minimize noisy operations (e.g. avoiding password resets when group takeovers exist).
3. **Viper Predictive (Machine Learning Engine)**:
   - Uses a **Random Forest Classifier** trained on enterprise Active Directory telemetry.
   - Solves the **Combinatorial Blindspot** of static graph algorithms where combinations of individually viable steps cause execution failures in live Active Directory environments.
   - Generates calibrated **Confidence Scores ($60\% - 95\%$)** across paths to recommend the highest-reliability vector.

### Phase 3: Automated Privilege Escalation Engine
* **Modular Step-by-Step Execution**: Executes attack path actions via direct LDAP3 and Impacket RPC protocols.
* **Supported Privilege Exploits**:
  - Group Membership Injections (`AddMember`)
  - DACL Modifications (`WriteDacl`, `GenericAll`, `GenericWrite`)
  - Ownership Seizures (`Owns`, `WriteOwner`)
  - Account Password Resets (`ForceChangePassword`)
  - Domain Credential Dumps (`DCSync` via DRSUAPI replication)
* **Real-time Live Execution Feed**: Interactive terminal interface providing instant status logs, new credentials, and step verification.

### Phase 4: Surgical Remediation Script Builder
* **Zero-Downtime Defense**: Automatically compiles chosen attack path edges into an idempotent, standalone PowerShell script (`.ps1`).
* **19 Supported Edge Conditions**: Tailored removal templates for all 19 recognized Active Directory relationship vectors.
* **Safe SACL Restoration**: Automatically returns hijacked object ownership back to `Domain Admins` and strips unneeded ACEs without disrupting normal domain operations.
* **Archived Script Repository**: Built-in script management, preview, and download vault in the web UI.

---

## 🎯 The 19 Accepted Active Directory Edges

ViperACL strictly models, validates, and remediates the **19 universal Active Directory relationship vectors**:

| # | Relationship | Target AD Class | Offensive Technique | Defensive Remediation |
|---|---|---|---|---|
| 1 | `MemberOf` | `Group` | Passive Token Inheritance | `Remove-ADGroupMember` |
| 2 | `DCSync` | `Domain` | DRSUAPI Hash Replication | Strips `DS-Replication` Extended Rights |
| 3 | `AddMember` | `Group` | Injects Member to High-Priv Group | Removes Self-Membership / `WriteProperty` ACE |
| 4 | `GenericWrite` | `Group` | Overwrites Group Attributes | Revokes `GenericWrite` / `WriteProperty` ACE |
| 5 | `GenericAll` | `User` | Full Control over User Object | Strips `GenericAll` ACE from User DACL |
| 6 | `GenericAll` | `Group` | Full Control over Group Object | Strips `GenericAll` ACE from Group DACL |
| 7 | `GenericAll` | `Domain` | Full Control over Domain Root | Strips `GenericAll` ACE from Domain DACL |
| 8 | `AllExtendedRights` | `User` | Extended Rights on User Object | Removes `ExtendedRight` ACE |
| 9 | `AllExtendedRights` | `Domain` | Extended Rights on Domain Root | Removes `ExtendedRight` ACE from Domain Root |
| 10 | `WriteDacl` | `User` | Discretionary ACL Modification | Strips `WriteDacl` ACE from User Object |
| 11 | `WriteDacl` | `Group` | Discretionary ACL Modification | Strips `WriteDacl` ACE from Group Object |
| 12 | `WriteDacl` | `Domain` | Discretionary ACL Modification | Strips `WriteDacl` ACE from Domain Root |
| 13 | `Owns` | `User` | Direct Object Ownership | Restores Owner to `Domain Admins` |
| 14 | `Owns` | `Group` | Direct Group Ownership | Restores Owner to `Domain Admins` |
| 15 | `Owns` | `Domain` | Direct Domain Root Ownership | Restores Owner to `Domain Admins` |
| 16 | `WriteOwner` | `User` | Seizes User Object Ownership | Strips `WriteOwner` ACE |
| 17 | `WriteOwner` | `Group` | Seizes Group Object Ownership | Strips `WriteOwner` ACE |
| 18 | `WriteOwner` | `Domain` | Seizes Domain Object Ownership | Strips `WriteOwner` ACE |
| 19 | `ForceChangePassword` | `User` | Resets Account Password | Strips `User-Force-Change-Password` GUID ACE |

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- **Python**: Python 3.10 or higher
- **Docker**: Docker & Docker Compose (used for the local Neo4j database container)

### 2. Setup Environment
```bash
# Clone the repository
git clone https://github.com/YourUsername/ViperACL.git
cd ViperACL

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 💻 Usage

### Start the ViperACL Web Application
Launch the complete platform with a single command:
```bash
source venv/bin/activate
python3 viperacl.py --port 8000
```
> **Note**: On startup, `viperacl.py` automatically initializes project storage, verifies database connectivity, and bootstraps the local Neo4j Docker container in the background.

Open your browser and navigate to: **`http://127.0.0.1:8000`**

### Run Automated Test Suite
To verify environment readiness and run all unit and integration tests:
```bash
pytest
```

---

## 🛡️ Forensic Audit Trail & Evidence Logging

Every operation performed across the ViperACL platform (project lifecycle, SharpHound ingestion, algorithm decisions, exploit executions, and remediation script compilation) is permanently logged to:
```text
data/logs/viperacl_audit.jsonl
```
Each entry captures:
- `timestamp`: ISO-8601 UTC timestamp
- `category`: `PROJECT`, `INGEST`, `PATHFINDER`, `PRIVESC`, `REMEDIATION`, `SYSTEM`
- `event_type`: Specific dot-delimited action identifier
- `severity`: `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- `project_id`: Scoped active project
- `details`: Contextual non-sensitive payload parameters

---

## ⚠️ Disclaimer

**ViperACL is designed exclusively for authorized penetration testing, red teaming, security auditing, and Active Directory defensive hardening.**
Unauthorized access to computer systems or networks is strictly illegal. Always obtain explicit written authorization from network owners before running Active Directory collection, pathfinding, or privilege escalation operations.
