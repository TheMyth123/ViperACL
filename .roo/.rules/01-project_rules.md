# Project Overview: ViperACL
ViperACL is an automated Active Directory (AD) attack path navigator. It utilizes graph theory and machine learning to map, prioritize, validate, and remediate Access Control List (ACL) misconfigurations. The project is strictly designed for safe, controlled execution within authorized enterprise environments and heavily emphasizes state-rollback and surgical remediation.

## Global Tech Stack & Dependencies
- **Core Language**: Python
- **Data Manipulation**: Pandas
- **Machine Learning**: Scikit-Learn (Random Forest)
- **Network Protocol / Exploitation**: Impacket
- **Graph Database**: Neo4j (Cypher queries)
- **Remediation**: PowerShell (`.ps1`)

---

## Directory Architecture & Module Rules

### 1. `core/ingestor` (Data Ingestion Module)
**Role:** Ingest raw Active Directory data (typically JSON from SharpHound), flatten and format the data, and build the visual/mathematical relationship graph.
* **Libraries:** `pandas`, `json`, `neo4j`.
* **Rules:**
    * All raw JSON data must be parsed and flattened into 2D structures using Pandas DataFrames (`read_json`, `json_normalize`).
    * Perform rigorous data cleaning: Immediately drop corrupted/empty rows (`dropna`).
    * Execute categorical text encoding: Convert string-based ACL permissions (e.g., 'GenericAll', 'WriteDACL') into numerical formats suitable for downstream ML ingestion.
    * Map relationships structurally as Nodes (Users, Computers, Groups) and Edges (ACL permissions, active logon sessions).

### 2. `core/pathfinder` (Predictive Scoring Module)
**Role:** Apply shortest-path algorithms alongside a Random Forest classifier to predict the success probability and expected noise rate of discovered attack paths.
* **Libraries:** `scikit-learn` (`RandomForestClassifier`, `train_test_split`, `metrics`), `pandas`.
* **Rules:**
    * **Never** use linear models (like Logistic Regression) or Support Vector Machines (SVM). Rely strictly on `RandomForestClassifier` to handle the non-linear complexity of AD attack graphs.
    * Utilize Out-of-Bag (OOB) sampling to handle unbalanced network security data effectively.
    * Calculate risk based heavily on specific environmental factors such as "Number of path hops" and "Type of ACL permission."
    * Outputs must include a strict percentage-based success probability score for each path, rather than qualitative rankings.

### 3. `core/abuse` (Automated Exploitation Engine)
**Role:** Safely execute multi-stage ACL exploits (e.g., Kerberoasting, DCSync, forced password changes) in real-time to validate paths identified by the pathfinder.
* **Libraries:** `impacket`.
* **Rules:**
    * **CRITICAL SAFETY GUARDRAIL:** Every single exploitation routine must track all network and permission changes. You must implement a mandatory **State Rollback and Restoration** feature to revert all permissions back to their pre-attack state upon completion.
    * Use `impacket` modules for silent, protocol-level interactions (LDAP, SMB, Kerberos ticket requests) without dropping malicious executables to disk.
    * Ensure the engine supports chaining multiple vulnerabilities (multi-hop escalations) continuously.
    * Must automatically generate a step-by-step Proof of Concept (PoC) execution log/report upon successful exploitation.

### 4. `core/remediation` (Remediation Script Generator)
**Role:** Generate exact, mathematically validated PowerShell scripts to surgically remove or modify vulnerable permissions without breaking legacy infrastructure.
* **Output Format:** `.ps1` (PowerShell scripts).
* **Rules:**
    * **No live execution:** The module must only *generate* the script text for human review. It must never automatically apply the remediation directly to the live domain server.
    * Scripts must be highly targeted (surgical, one-to-one ACL fixes) aimed at severing the exact relationship edge. Do not generate broad Group Policy Objects (GPOs) for database-level ACL fixes.
    * Ensure the generated code includes comments explaining which specific edge/node relationship is being terminated based on the pathfinder's risk score.

---

## General Coding Standards & Workflows
- **Environment:** Code should be written assuming execution within a Kali Linux virtualized sandbox (to prevent EDR/AV blocking legitimate Impacket scripts during development).
- **Error Handling:** Implement strict `try/except` blocks across network-facing modules (Abuse) and database-facing modules (Ingestor) to prevent silent failures.
- **State Integrity:** Data must logically flow from `Ingestor` -> `Pathfinder` -> `Abuse` -> `Remediation`.