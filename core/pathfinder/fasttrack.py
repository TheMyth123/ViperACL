# core/pathfinder/fasttrack.py
from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)
from .tactical import COST_MAP


def run_fasttrack(db, source_name, target_name, max_hops=15):
    """
    Viper FastTrack Engine: Finds the path with the absolute fewest hops, 
    enforcing DCSync combination and strict accepted edges across all steps.
    """
    hops_limit = max(1, min(int(max_hops), 50))
    
    try:
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

    # Step 1: Find shortest paths using allShortestPaths
    q_short = f"""
    MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
    MATCH p = allShortestPaths((source)-[:{rel_pattern}*..{hops_limit}]->(target))
    RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    LIMIT 25
    """

    records = db.run_query(q_short, parameters=params) or []
    dcsync_cache = {}
    seen_signatures = set()

    for rec in records:
        raw_path = rec.get("p")
        if not raw_path:
            continue

        path = enrich_path_node_labels(raw_path, rec.get("node_labels"))
        normalized = normalize_path_dcsync(path, db, cache=dcsync_cache)

        if not is_valid_path(normalized, db):
            continue

        sig = get_path_signature(normalized)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        hops = (len(normalized) - 1) // 2
        return [{"p": normalized, "hops": hops}]

    # Step 2: If no allShortestPaths matched valid accepted edges, check incremental depths
    min_hops = records[0].get("hops") if records else 1
    if min_hops < hops_limit:
        max_search = min(min_hops + 3, hops_limit)
        for h in range(min_hops + 1, max_search + 1):
            qh = f"""
            MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
            MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
            RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
            LIMIT 15
            """
            extra_records = db.run_query(qh, parameters=params) or []
            for rec in extra_records:
                raw_path = rec.get("p")
                if not raw_path:
                    continue

                path = enrich_path_node_labels(raw_path, rec.get("node_labels"))
                normalized = normalize_path_dcsync(path, db, cache=dcsync_cache)

                if not is_valid_path(normalized, db):
                    continue

                sig = get_path_signature(normalized)
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                hops = (len(normalized) - 1) // 2
                return [{"p": normalized, "hops": hops}]

    return []