# core/pathfinder/predictive.py
import pandas as pd
from .tactical import COST_MAP 

# Dynamically sort relationships alphabetically to ensure consistent column order
REL_TYPES = sorted(list(COST_MAP.keys()))
FEATURE_COLUMNS = ['Hops', 'TotalCost', 'MaxCost'] + [f'Count_{rel}' for rel in REL_TYPES]

def extract_features(path):
    """Translates a Cypher path into ML features, including counts of all relationship types."""
    hops = (len(path) - 1) // 2
    total_cost = 0
    max_cost = 0
    
    # Initialize a counter dictionary for every relationship type to 0
    rel_counts = {rel: 0 for rel in REL_TYPES}
    
    for i in range(1, len(path), 2):
        rel_type = path[i]
        cost = COST_MAP.get(rel_type, 10)
        
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

def run_predictive(db, source_name, target_name, model, max_hops=15, ml_threshold=0.50):
    """
    Viper Predictive Engine: Evaluates multiple paths using Random Forest probabilities.
    Ensures strictly one-way acyclic attack chains from source to target, respecting
    max_hops limit and ml_threshold confidence filter.
    """
    try:
        rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get("rel") for row in rel_rows if row.get("rel")}
    except Exception:
        present_rels = set()

    allowed_rels = [r for r in COST_MAP.keys() if r in present_rels]
    if not allowed_rels:
        return None

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))
    threshold_pct = (ml_threshold * 100) if ml_threshold <= 1.0 else float(ml_threshold)

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
    }

    # 1. First retrieve all shortest paths efficiently
    q_shortest = f"""
    MATCH p = allShortestPaths((source {{name: $source_name}})-[:{rel_pattern}*..{hops_limit}]->(target {{name: $target_name}}))
    RETURN p, length(p) AS hops
    """
    shortest_records = db.run_query(q_shortest, parameters=params) or []
    candidate_paths = [r["p"] for r in shortest_records if "p" in r]
    
    min_hops = shortest_records[0].get("hops") if shortest_records else None

    # 2. Gather subsequent hop-length paths to explore varied tactical vectors (up to min_hops + 3)
    if min_hops and min_hops < hops_limit:
        max_search_hop = min(min_hops + 3, hops_limit)
        for h in range(min_hops + 1, max_search_hop + 1):
            if len(candidate_paths) >= 40:
                break
            qh = f"""
            MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
            MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
            WHERE none(n IN nodes(p)[0..-2] WHERE toUpper(n.name) = toUpper($target_name))
            AND none(n IN nodes(p)[1..] WHERE toUpper(n.name) = toUpper($source_name))
            RETURN p
            LIMIT 20
            """
            extra_records = db.run_query(qh, parameters=params) or []
            candidate_paths.extend([r["p"] for r in extra_records if "p" in r])

    if not candidate_paths:
        return None

    scored_paths = []
    seen_signatures = set()
    
    for path in candidate_paths:
        # Ensure strictly simple path (no repeated nodes)
        nodes = [path[i].get("name") if isinstance(path[i], dict) else getattr(path[i], "get", lambda k: str(path[i]))("name") for i in range(0, len(path), 2)]
        if len(nodes) != len(set(nodes)):
            continue
            
        rels = [path[i] if isinstance(path[i], str) else getattr(path[i], "type", str(path[i])) for i in range(1, len(path), 2)]
        sig = tuple(zip(nodes[:-1], rels, nodes[1:]))
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        features = extract_features(path)
        df_features = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        
        success_prob = model.predict_proba(df_features)[0][1] 
        prob_pct = round(success_prob * 100, 2)

        # Enforce ML threshold filter
        if prob_pct < threshold_pct:
            continue
        
        scored_paths.append({
            "path": path,
            "features": features,
            "success_probability": prob_pct
        })
        
    scored_paths.sort(key=lambda x: x["success_probability"], reverse=True)
    
    return scored_paths[:10]