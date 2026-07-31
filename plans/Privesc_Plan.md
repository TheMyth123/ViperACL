Phase 3: ViperACL Privesc Architecture Plan

## 1. Architectural Overview
The **Privesc** phase operates as an automated state-machine or "Task Manager." It receives a prioritized path (an array of nodes and edges) from the Pathfinder phase and attempts to execute them sequentially. 

Since each relationship requires a different operational approach, the architecture will use a **Factory Pattern** combined with a **Context Manager**. The Context Manager will keep track of the current compromised state (e.g., newly acquired credentials, modified DACLs) as the tool progresses along the path.

---

## 2. Directory Structure

All components will be housed within the `core/privesc/` directory to maintain modularity.

```text
core/
└── privesc/
    ├── __init__.py
    ├── engine.py              # The Core Task Manager
    ├── state_context.py       # Tracks current credentials, sessions, and rollback data
    ├── factory.py             # Maps relationship types to the correct execution module
    └── modules/               # Directory containing the relationship handlers
        ├── __init__.py
        ├── base_module.py     # Abstract Base Class for all modules
        ├── passive.py         # Handlers: MemberOf, DCSync, GetChanges(All)
        ├── standard.py        # Handlers: AddMember, GenericWrite, GenericAll
        ├── structural.py      # Handlers: WriteDacl, Owns, WriteOwner
        └── destructive.py     # Handlers: ForceChangePassword
```