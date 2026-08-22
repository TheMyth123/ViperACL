# core/pathfinder/tactical.py
from .rules import (
    enrich_path_node_labels,
    get_node_type,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)

COST_MAP = {
    # Passive / no active modification
    ('MemberOf', 'GROUP'): 0,

    # Direct domain credential access
    ('DCSync', 'DOMAIN'): 0,

    # Direct group membership modification
    ('AddMember', 'GROUP'): 1,
    ('GenericWrite', 'GROUP'): 1,

    # GenericAll has different execution impact by target
    ('GenericAll', 'USER'): 3,
    ('GenericAll', 'GROUP'): 1,
    ('GenericAll', 'DOMAIN'): 0,

    # Extended rights
    ('AllExtendedRights', 'USER'): 3,
    ('AllExtendedRights', 'DOMAIN'): 0,

    # DACL modification introduces an additional privilege-granting step
    ('WriteDacl', 'USER'): 4,
    ('WriteDacl', 'GROUP'): 2,
    ('WriteDacl', 'DOMAIN'): 1,

    # Ownership requires ownership/control transition before abuse
    ('Owns', 'USER'): 4,
    ('Owns', 'GROUP'): 2,
    ('Owns', 'DOMAIN'): 1,

    # WriteOwner requires an ownership transition before the actual abuse
    ('WriteOwner', 'USER'): 5,
    ('WriteOwner', 'GROUP'): 3,
    ('WriteOwner', 'DOMAIN'): 2,

    # Direct password reset
    ('ForceChangePassword', 'USER'): 5,
}


def get_edge_cost(rel, target_node_or_type, db=None, project_id=None) -> int:
    """Returns tactical cost for a (relationship, target) pair."""
    rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
    known_types = {"USER", "GROUP", "DOMAIN", "COMPUTER", "GPO", "OU", "CONTAINER"}

    if isinstance(target_node_or_type, str) and target_node_or_type.upper() in known_types:
        target_type = target_node_or_type.upper()
    else:
        target_type = get_node_type(target_node_or_type, db, project_id=project_id).upper()

    cost = COST_MAP.get((rel_type, target_type))
    if cost is not None:
        return cost

    rel_lower = rel_type.lower()
    tgt_lower = target_type.lower()
    for (k_rel, k_tgt), val in COST_MAP.items():
        if k_rel.lower() == rel_lower and k_tgt.lower() == tgt_lower:
            return val

    return 10


def calculate_path_weight(path, db=None, project_id=None) -> int:
    """Calculates total tactical weight of a path considering relationship and target node type."""
    total = 0
    if not isinstance(path, list) or len(path) < 3:
        return total

    for i in range(1, len(path) - 1, 2):
        rel = path[i]
        target_node = path[i + 1]
        total += get_edge_cost(rel, target_node, db, project_id=project_id)
    return total


def run_tactical(db, source_name, target_name, max_hops=15, project_id=None):
    """
    Viper Tactical Engine: Finds the lowest-cost path using tactical weights,
    enforcing DCSync combination and strict 19 end conditions within the active project graph.
    """
    try:
        if project_id:
            rel_rows = db.run_query("MATCH ()-[r {project_id: $pid}]->() RETURN DISTINCT type(r) AS rel", {"pid": project_id})
        else:
            rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get('rel') for row in rel_rows if row.get('rel')}
    except Exception:
        present_rels = set()

    cost_map_rels = {k[0] for k in COST_MAP.keys()}
    if "DCSync" in cost_map_rels:
        cost_map_rels.update({"GetChanges", "GetChangesAll"})

    allowed_rels = [r for r in cost_map_rels if r in present_rels]
    if not allowed_rels:
        return []

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
    }
    if project_id:
        params["pid"] = project_id
        src_node = "(source {name: $source_name, project_id: $pid})"
        tgt_node = "(target {name: $target_name, project_id: $pid})"
        rel_filter = "WHERE ALL(r IN relationships(p) WHERE r.project_id = $pid)"
    else:
        src_node = "(source {name: $source_name})"
        tgt_node = "(target {name: $target_name})"
        rel_filter = ""

    # Step 1: determine minimum hop length to bound search
    q_short = f"""
    MATCH p = shortestPath({src_node}-[:{rel_pattern}*1..{hops_limit}]->{tgt_node})
    {rel_filter}
    RETURN length(p) AS min_hops
    """
    short_rows = db.run_query(q_short, parameters=params)
    if not short_rows or not short_rows[0].get("min_hops"):
        return []

    min_hops = short_rows[0]["min_hops"]
    search_depth = min(min_hops + 3, hops_limit)

    # Step 2: query candidate paths within bounded depth
    query = f"""
    MATCH {src_node}, {tgt_node}
    MATCH p = (source)-[:{rel_pattern}*1..{search_depth}]->(target)
    {rel_filter}
    RETURN p, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    LIMIT 60
    """

    candidate_records = db.run_query(query, parameters=params) or []
    if not candidate_records:
        return []

    dcsync_cache = {}
    valid_paths = []
    seen_signatures = set()

    for record in candidate_records:
        raw_path = record.get("p")
        if not raw_path:
            continue

        path = enrich_path_node_labels(raw_path, record.get("node_labels"))
        normalized = normalize_path_dcsync(path, db, cache=dcsync_cache, project_id=project_id)

        if not is_valid_path(normalized, db, project_id=project_id):
            continue

        sig = get_path_signature(normalized)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        hops = (len(normalized) - 1) // 2
        weight = calculate_path_weight(normalized, db=db, project_id=project_id)

        valid_paths.append({
            "p": normalized,
            "pathWeight": weight,
            "hops": hops,
        })

    if not valid_paths:
        return []

    # Lowest cost path first, then fewest hops
    valid_paths.sort(key=lambda x: (x["pathWeight"], x["hops"]))
    return [valid_paths[0]]