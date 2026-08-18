# core/pathfinder/tactical.py
from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_end_condition,
    normalize_path_dcsync,
)

COST_MAP = {
    # Passive / Already possessed
    'MemberOf': 0,
    'DCSync': 0,          
    'GetChanges': 0,      
    'GetChangesAll': 0,   
    
    # Active Modifications (Standard)
    'AddMember': 1,
    'GenericWrite': 1,
    'GenericAll': 1,
    'AllExtendedRights': 2,
    
    # Structural Changes (More complex)
    'WriteDacl': 2,
    'Owns': 2,
    'WriteOwner': 3,      
    
    # High Visibility / Destructive
    'ForceChangePassword': 5 
}


def calculate_path_weight(path) -> int:
    """Calculates total tactical weight of a path."""
    total = 0
    for i in range(1, len(path) - 1, 2):
        rel = path[i]
        rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
        total += COST_MAP.get(rel_type, 10)
    return total


def run_tactical(db, source_name, target_name, max_hops=15):
    """
    Viper Tactical Engine: Finds the lowest-cost path using tactical weights,
    enforcing DCSync combination and strict 19 end conditions.
    """
    try:
        rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get('rel') for row in rel_rows if row.get('rel')}
    except Exception:
        present_rels = set()

    allowed_rels = [r for r in COST_MAP.keys() if r in present_rels]
    if not allowed_rels:
        return []

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
    }

    # Step 1: determine minimum hop length to bound search
    q_short = f"""
    MATCH p = shortestPath((source {{name: $source_name}})-[:{rel_pattern}*1..{hops_limit}]->(target {{name: $target_name}}))
    RETURN length(p) AS min_hops
    """
    short_rows = db.run_query(q_short, parameters=params)
    if not short_rows or not short_rows[0].get("min_hops"):
        return []

    min_hops = short_rows[0]["min_hops"]
    search_depth = min(min_hops + 3, hops_limit)

    # Step 2: query candidate paths within bounded depth
    query = f"""
    MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
    MATCH p = (source)-[:{rel_pattern}*1..{search_depth}]->(target)
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
        normalized = normalize_path_dcsync(path, db, cache=dcsync_cache)

        if not is_valid_end_condition(normalized, db):
            continue

        sig = get_path_signature(normalized)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        hops = (len(normalized) - 1) // 2
        weight = calculate_path_weight(normalized)

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