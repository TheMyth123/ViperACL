"""
ViperACL Pathfinder Rules & Validation Engine.

Enforces:
1. DCSync Synthesis & Deduplication:
   When both GetChanges and GetChangesAll point from a principal to the same Domain,
   they are normalized into a single 'DCSync' relationship.
2. Strict Accepted Edges:
   Every hop in a path (start, intermediate, or end) must strictly match one of the
   19 accepted (Relationship, TargetType) definitions.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


# The 19 strictly accepted edges across all steps: (Relationship, Target AD Class)
ACCEPTED_EDGES: Set[Tuple[str, str]] = {
    ("MemberOf", "Group"),
    ("DCSync", "Domain"),
    ("AddMember", "Group"),
    ("GenericWrite", "Group"),
    ("GenericAll", "User"),
    ("GenericAll", "Group"),
    ("GenericAll", "Domain"),
    ("AllExtendedRights", "User"),
    ("AllExtendedRights", "Domain"),
    ("WriteDacl", "User"),
    ("WriteDacl", "Group"),
    ("WriteDacl", "Domain"),
    ("Owns", "User"),
    ("Owns", "Group"),
    ("Owns", "Domain"),
    ("WriteOwner", "User"),
    ("WriteOwner", "Group"),
    ("WriteOwner", "Domain"),
    ("ForceChangePassword", "User"),
}


def get_node_type(node: Any, db: Optional[Any] = None, project_id: Optional[str] = None) -> str:
    """Extract standard AD object type ('User', 'Group', 'Domain', 'Computer', etc.) from node."""
    if not node:
        return ""

    labels = []
    if isinstance(node, dict):
        labels = node.get("labels") or []
        if not labels and "name" in node and db is not None:
            try:
                if project_id:
                    res = db.run_query(
                        "MATCH (n {name: $name, project_id: $pid}) RETURN labels(n) AS labels LIMIT 1",
                        {"name": node["name"], "pid": project_id},
                    )
                else:
                    res = db.run_query(
                        "MATCH (n {name: $name}) RETURN labels(n) AS labels LIMIT 1",
                        {"name": node["name"]},
                    )
                if res and res[0].get("labels"):
                    labels = res[0]["labels"]
            except Exception:
                labels = []
    elif hasattr(node, "labels"):
        labels = list(node.labels)
    elif hasattr(node, "get"):
        labels = node.get("labels", [])

    labels_upper = {str(lbl).upper() for lbl in labels}

    if "USER" in labels_upper:
        return "User"
    if "GROUP" in labels_upper:
        return "Group"
    if "DOMAIN" in labels_upper:
        return "Domain"
    if "COMPUTER" in labels_upper:
        return "Computer"
    if "GPO" in labels_upper:
        return "GPO"
    if "OU" in labels_upper:
        return "OU"
    if "CONTAINER" in labels_upper:
        return "Container"

    # Fallback heuristic from node name string when labels are absent
    raw_name = node if isinstance(node, str) else (node.get("name") if isinstance(node, dict) else getattr(node, "name", str(node)))
    name_str = str(raw_name or "").upper().strip()
    if name_str:
        if name_str.endswith((".LOCAL", ".CORP", ".LAN", ".INTERNAL", ".COM", ".NET", ".ORG")) and "@" not in name_str:
            return "Domain"
        if any(w in name_str for w in ("DEPARTMENT", "DEPT", "OPERATIONS", "OPS", "ADMINS", "GROUP", "GRP", "HELPDESK", "USERS_GRP", "SECURITY_OPS", "INFRASTRUCTURE", "DEVELOPERS", "MANAGERS")):
            return "Group"
        if name_str.endswith("$") or any(w in name_str for w in ("COMP_", "DC0", "WS-", "SRV-", "DESKTOP-")):
            return "Computer"
        if "@" in name_str or "_" in name_str:
            return "User"

    return ""


def check_has_dcsync_pair(
    db: Any, source_node: Any, target_node: Any, cache: Optional[Dict[Tuple[str, str], bool]] = None, project_id: Optional[str] = None
) -> bool:
    """
    Checks whether source_node has both GetChanges and GetChangesAll
    pointing to target_node in the database.
    """
    if db is None:
        return False

    src_id = source_node.get("objectid") if isinstance(source_node, dict) else getattr(source_node, "objectid", None)
    src_name = source_node.get("name") if isinstance(source_node, dict) else getattr(source_node, "name", None)

    tgt_id = target_node.get("objectid") if isinstance(target_node, dict) else getattr(target_node, "objectid", None)
    tgt_name = target_node.get("name") if isinstance(target_node, dict) else getattr(target_node, "name", None)

    cache_key = (str(src_id or src_name or ""), str(tgt_id or tgt_name or ""), str(project_id or ""))
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    params: Dict[str, Any] = {}
    if src_id and tgt_id:
        src_clause = "s.objectid = $src_id"
        tgt_clause = "t.objectid = $tgt_id"
        params["src_id"] = src_id
        params["tgt_id"] = tgt_id
    else:
        src_clause = "toUpper(s.name) = toUpper($src_name)"
        tgt_clause = "toUpper(t.name) = toUpper($tgt_name)"
        params["src_name"] = src_name or ""
        params["tgt_name"] = tgt_name or ""

    if project_id:
        src_clause += " AND s.project_id = $pid"
        tgt_clause += " AND t.project_id = $pid"
        params["pid"] = project_id
        gc_match = "MATCH (s)-[:GetChanges {project_id: $pid}]->(t)"
        gca_match = "MATCH (s)-[:GetChangesAll {project_id: $pid}]->(t)"
    else:
        gc_match = "MATCH (s)-[:GetChanges]->(t)"
        gca_match = "MATCH (s)-[:GetChangesAll]->(t)"

    query = f"""
    MATCH (s), (t)
    WHERE {src_clause} AND {tgt_clause}
    RETURN 
        EXISTS {{ {gc_match} }} AS has_gc,
        EXISTS {{ {gca_match} }} AS has_gca
    LIMIT 1
    """
    try:
        res = db.run_query(query, params)
        if res:
            row = res[0]
            has_pair = bool(row.get("has_gc") and row.get("has_gca"))
        else:
            has_pair = False
    except Exception:
        has_pair = False

    if cache is not None:
        cache[cache_key] = has_pair

    return has_pair


def normalize_path_dcsync(
    path: List[Any], db: Optional[Any] = None, cache: Optional[Dict[Tuple[str, str], bool]] = None, project_id: Optional[str] = None
) -> List[Any]:
    """
    Normalizes a path representation by transforming GetChanges / GetChangesAll
    pointing to a Domain into 'DCSync' if the principal has both replication rights.
    """
    if not isinstance(path, list) or len(path) < 3:
        return path

    normalized = list(path)
    for i in range(1, len(normalized) - 1, 2):
        src_node = normalized[i - 1]
        rel = normalized[i]
        tgt_node = normalized[i + 1]

        rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
        tgt_type = get_node_type(tgt_node, db, project_id=project_id)

        if tgt_type == "Domain" and rel_type in ("GetChanges", "GetChangesAll"):
            if check_has_dcsync_pair(db, src_node, tgt_node, cache=cache, project_id=project_id):
                normalized[i] = "DCSync"

    return normalized


def is_valid_edge(rel: Any, target_node: Any, db: Optional[Any] = None, project_id: Optional[str] = None) -> bool:
    """
    Checks if a single edge satisfies one of the 19 accepted (Relationship, TargetType) pairs.
    """
    rel_str = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
    target_type = get_node_type(target_node, db, project_id=project_id)

    if not target_type:
        return False

    for allowed_rel, allowed_type in ACCEPTED_EDGES:
        if rel_str.lower() == allowed_rel.lower() and target_type.lower() == allowed_type.lower():
            return True

    return False


def is_valid_path(path: List[Any], db: Optional[Any] = None, project_id: Optional[str] = None) -> bool:
    """
    Validates that every step in the path is one of the strictly accepted 19 edge types.
    """
    if not isinstance(path, list) or len(path) < 3:
        return False

    for i in range(1, len(path) - 1, 2):
        rel = path[i]
        target_node = path[i + 1]
        if not is_valid_edge(rel, target_node, db, project_id=project_id):
            return False

    return True


def get_path_signature(path: List[Any]) -> Tuple[Any, ...]:
    """Generates a unique tuple signature of a path for deduplication."""
    sig_elements = []
    for elem in path:
        if isinstance(elem, dict):
            sig_elements.append(elem.get("name") or elem.get("objectid") or str(elem))
        elif isinstance(elem, str):
            sig_elements.append(elem)
        else:
            name = getattr(elem, "name", None) or getattr(elem, "type", None) or str(elem)
            sig_elements.append(name)
    return tuple(sig_elements)


def enrich_path_node_labels(path: List[Any], node_labels: Optional[List[List[str]]]) -> List[Any]:
    """Attaches node label metadata to dict nodes within a path list."""
    if not node_labels or not isinstance(path, list):
        return path

    node_idx = 0
    for i in range(0, len(path), 2):
        if node_idx < len(node_labels):
            if isinstance(path[i], dict):
                path[i]["labels"] = node_labels[node_idx]
        node_idx += 1

    return path
