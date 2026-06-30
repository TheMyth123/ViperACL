# Phase 4: ViperACL Remediation Architecture Plan

## 1. Architectural Overview
The **Remediation** phase operates as a **Script Builder**. It is designed to take an attack path (specifically, the list of relationships a user wants to sever) and generate a single, unified PowerShell script (`.ps1`). This script can then be executed by a network administrator to securely remove those specific privileges, effectively mitigating the attack path.

This phase is entirely defensive and operates offline by generating text based on the output of previous phases.

---

## 2. Directory Structure

All components will be housed within the `core/remediation/` directory to maintain modularity.

```text
core/
└── remediation/
    ├── __init__.py
    ├── engine.py              # Orchestrator: receives relationships, outputs .ps1
    ├── builder.py             # Logic Mapper: injects variables into templates
    └── ps_templates.py        # Template Library: stores raw PowerShell strings
```

---

## 3. Core Files & Brief Content

### `core/remediation/engine.py` (The Orchestrator)
**Purpose:** The main entry point. It receives a list of relationships to fix, calls the builder for each one, and writes the final PowerShell script.
**Key Components:**
* `class RemediationEngine`:
    * `def __init__(self, output_path="viperacl_remediation.ps1")`: Sets the output destination.
    * `def generate_script(self, remediation_targets: list)`: Iterates through the targets. For each item (e.g., `{'type': 'GenericAll', 'source': 'UserA', 'target': 'GroupB'}`), it asks the `builder.py` for the code block. It prepends a standard warning/logging header to the script and writes the final output to disk.

### `core/remediation/builder.py` (The Logic Mapper)
**Purpose:** Translates a relationship into a specific PowerShell command by injecting the source and target names into the correct template.
**Key Components:**
* `class ScriptBuilder`:
    * `def get_remediation_block(self, rel_type: str, source: str, target: str) -> str`: Contains a lookup mechanism. It maps `rel_type` (like `'AddMember'`) to the correct template in `ps_templates.py`. It then uses Python's `.format(source=source, target=target)` to populate the script and returns the customized block.

### `core/remediation/ps_templates.py` (The Template Library)
**Purpose:** A configuration file holding raw PowerShell strings. Keeping this separate makes the Python logic clean and allows for easy updates to the PowerShell commands.
**Key Components:**
Dictionaries or string variables. Examples:
* `MEMBER_OF_REMOVAL`: Script to run `Remove-ADGroupMember`.
* `GENERIC_ACL_REMOVAL`: Script to get the target's ACL, find the specific source user's rights, remove that Access Control Entry (ACE), and `Set-Acl`.

---

## 4. Relationship to PowerShell Mapping (ps_templates.py)

The templates map directly to the `COST_MAP` used in earlier phases.

| Category | Relationships | Remediation Strategy (PowerShell Concept) |
| :--- | :--- | :--- |
| **Standard Group/Identity** | `MemberOf` | **`Remove-ADGroupMember`**<br>Removes the source user from the target group. |
| **Active/Standard ACLs** | `GenericWrite`, `GenericAll`, `AddMember`, `AllExtendedRights` | **`Set-Acl` & `ActiveDirectoryRights`**<br>Fetches the target's ACL, identifies the ACE granting the specific right to the source user, removes the ACE, and applies the updated ACL. |
| **Domain-Level ACLs** | `DCSync`, `GetChanges`, `GetChangesAll` | **`Set-Acl` on the Domain Root**<br>Removes the `DS-Replication-Get-Changes` and `-All` extended rights from the domain root object. |
| **Structural ACLs** | `WriteDacl`, `WriteOwner`, `Owns` | **`Set-Acl` & Ownership transfer**<br>Removes the `WriteDacl`/`WriteOwner` ACEs. For `Owns`, sets the owner back to `Domain Admins`. |
| **Destructive ACLs** | `ForceChangePassword` | **`Set-Acl` & ExtendedRights**<br>Removes the specific `User-Force-Change-Password` extended right ACE from the target user's DACL. |

---

## 5. Execution Workflow

1.  **Input:** The CLI or GUI passes a list of relationships to remove to `RemediationEngine`. Example: `[{'type': 'ForceChangePassword', 'source': 'jdoe', 'target': 'bsmith'}]`
2.  **Mapping:** `Engine` passes this to `ScriptBuilder`.
3.  **Templating:** `ScriptBuilder` pulls the specific template from `ps_templates.py`, injects `jdoe` and `bsmith`, and returns the PowerShell snippet.
4.  **Compilation:** `Engine` aggregates all snippets.
5.  **Output:** `Engine` writes the aggregated snippets into `viperacl_remediation.ps1` with standard PowerShell comments explaining each step.