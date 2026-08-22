# core/pathfinder/predictive.py
import pandas as pd
from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)
from .tactical import COST_MAP, get_edge_cost

# Dynamically sort relationships alphabetically to ensure consistent column order
REL_TYPES = sorted(list({k[0] for k in COST_MAP.keys()} | {"GetChanges", "GetChangesAll"}))
FEATURE_COLUMNS = ['Hops', 'TotalCost', 'MaxCost'] + [f'Count_{rel}' for rel in REL_TYPES]

def extract_features(path, db=None, project_id=None):
    """Translates a Cypher path into ML features, including counts of all relationship types."""
    hops = (len(path) - 1) // 2
    total_cost = 0
    max_cost = 0
    
    # Initialize a counter dictionary for every relationship type to 0
    rel_counts = {rel: 0 for rel in REL_TYPES}
    
    for i in range(1, len(path) - 1, 2):
        rel = path[i]
        rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
        target_node = path[i + 1]
        cost = get_edge_cost(rel_type, target_node, db, project_id=project_id)
        
        total_cost += cost
        if cost > max_cost:
            max_cost = cost
            
        # Increment the specific relationship counter
        if rel_type in rel_counts:
            rel_counts[rel_type] += 1
            
    # Build the final numerical array perfectly matching FEATURE_COLUMNS
    features = [hops, total_cost, max_cost]
    for rel in REL_TYPES:
        features.append(rel_counts[rel])
        
    return features

def run_predictive(db, source_name, target_name, model, max_hops=15, ml_threshold=0.50, project_id=None):
    """
    Viper Predictive Engine: Evaluates multiple paths using Random Forest probabilities.
    Ensures strictly one-way acyclic attack chains from source to target within the active project graph.
    """
    try:
        if project_id:
            rel_rows = db.run_query("MATCH ()-[r {project_id: $pid}]->() RETURN DISTINCT type(r) AS rel", {"pid": project_id})
        else:
            rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get("rel") for row in rel_rows if row.get("rel")}
    except Exception:
        present_rels = set()

    cost_map_rels = {k[0] for k in COST_MAP.keys()}
    if "DCSync" in cost_map_rels:
        cost_map_rels.update({"GetChanges", "GetChangesAll"})

    allowed_rels = [r for r in cost_map_rels if r in present_rels]
    if not allowed_rels:
        return None

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))
    threshold_pct = (ml_threshold * 100) if ml_threshold <= 1.0 else float(ml_threshold)

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

    # 1. First retrieve all shortest paths efficiently
    q_shortest = f"""
    MATCH {src_node}, {tgt_node}
    MATCH p = allShortestPaths((source)-[:{rel_pattern}*..{hops_limit}]->(target))
    {rel_filter}
    RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    """
    candidate_records = db.run_query(q_shortest, parameters=params) or []
    
    min_hops = candidate_records[0].get("hops") if candidate_records else None

    # 2. Gather subsequent hop-length paths to explore varied tactical vectors (up to min_hops + 3)
    if min_hops and min_hops < hops_limit:
        max_search_hop = min(min_hops + 3, hops_limit)
        for h in range(min_hops + 1, max_search_hop + 1):
            if len(candidate_records) >= 50:
                break
            if project_id:
                qh = f"""
                MATCH {src_node}, {tgt_node}
                MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
                WHERE ALL(r IN relationships(p) WHERE r.project_id = $pid)
                AND none(n IN nodes(p)[0..-2] WHERE toUpper(n.name) = toUpper($target_name))
                AND none(n IN nodes(p)[1..] WHERE toUpper(n.name) = toUpper($source_name))
                RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
                LIMIT 20
                """
            else:
                qh = f"""
                MATCH {src_node}, {tgt_node}
                MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
                WHERE none(n IN nodes(p)[0..-2] WHERE toUpper(n.name) = toUpper($target_name))
                AND none(n IN nodes(p)[1..] WHERE toUpper(n.name) = toUpper($source_name))
                RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
                LIMIT 20
                """
            extra_records = db.run_query(qh, parameters=params) or []
            candidate_records.extend(extra_records)

    if not candidate_records:
        return None

    dcsync_cache = {}
    scored_paths = []
    seen_signatures = set()
    
    for record in candidate_records:
        raw_path = record.get("p")
        if not raw_path:
            continue

        # Ensure strictly simple path (no repeated nodes)
        nodes = [
            raw_path[i].get("name") if isinstance(raw_path[i], dict) else getattr(raw_path[i], "get", lambda k: str(raw_path[i]))("name")
            for i in range(0, len(raw_path), 2)
        ]
        if len(nodes) != len(set(nodes)):
            continue

        path = enrich_path_node_labels(raw_path, record.get("node_labels"))
        normalized = normalize_path_dcsync(path, db, cache=dcsync_cache, project_id=project_id)

        if not is_valid_path(normalized, db, project_id=project_id):
            continue

        sig = get_path_signature(normalized)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        features = extract_features(normalized, db=db, project_id=project_id)
        df_features = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        
        success_prob = model.predict_proba(df_features)[0][1] 
        prob_pct = round(success_prob * 100, 2)

        # Enforce ML threshold filter
        if prob_pct < threshold_pct:
            continue
        
        scored_paths.append({
            "path": normalized,
            "features": features,
            "success_probability": prob_pct
        })
        
    scored_paths.sort(key=lambda x: x["success_probability"], reverse=True)
    
    return scored_paths[:10] if scored_paths else None