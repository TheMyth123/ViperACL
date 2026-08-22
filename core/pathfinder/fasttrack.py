# core/pathfinder/fasttrack.py
from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)
from .tactical import COST_MAP, calculate_path_weight


def run_fasttrack(db, source_name, target_name, max_hops=15, project_id=None):
    """
    Viper FastTrack Engine: Finds the path with the absolute fewest valid hops, 
    enforcing DCSync combination and strict accepted edges across all steps within the active project graph.
    """
    hops_limit = max(1, min(int(max_hops), 50))
    
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

    # Step 1: Determine raw shortest hop length to bound initial search
    q_short = f"""
    MATCH p = shortestPath({src_node}-[:{rel_pattern}*1..{hops_limit}]->{tgt_node})
    {rel_filter}
    RETURN length(p) AS min_hops
    """
    short_rows = db.run_query(q_short, parameters=params)
    if not short_rows or not short_rows[0].get("min_hops"):
        return []

    min_hops = short_rows[0]["min_hops"]
    search_depth = min(min_hops + 4, hops_limit)

    # Step 2: Query candidate paths within bounded depth window
    query = f"""
    MATCH {src_node}, {tgt_node}
    MATCH p = (source)-[:{rel_pattern}*1..{search_depth}]->(target)
    {rel_filter}
    RETURN p, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    LIMIT 150
    """

    candidate_records = db.run_query(query, parameters=params) or []
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

    # Step 3: If no valid path was found within search_depth and search_depth < hops_limit, expand search
    if not valid_paths and search_depth < hops_limit:
        query_expanded = f"""
        MATCH {src_node}, {tgt_node}
        MATCH p = (source)-[:{rel_pattern}*{search_depth + 1}..{hops_limit}]->(target)
        {rel_filter}
        RETURN p, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
        LIMIT 150
        """
        expanded_records = db.run_query(query_expanded, parameters=params) or []
        for record in expanded_records:
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

    # Sort strictly by: 1) Absolute fewest valid hops, 2) Lowest path weight as tiebreaker
    valid_paths.sort(key=lambda x: (x["hops"], x["pathWeight"]))
    return [valid_paths[0]]