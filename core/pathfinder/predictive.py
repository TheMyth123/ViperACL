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

def run_predictive(db, source_name, target_name, model):
    """
    Viper Predictive Engine: Evaluates multiple paths using Random Forest probabilities.
    """
    query = """
    // Node definitions integrated to prevent Cartesian product warnings
    MATCH p = (source {name: $source_name})-[*1..10]->(target {name: $target_name})
    WHERE all(r IN relationships(p) WHERE type(r) IN keys($weight_map))
    RETURN p
    LIMIT 5
    """
    
    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
        "weight_map": COST_MAP
    }
    
    raw_results = db.run_query(query, parameters=params)
    if not raw_results:
        return None

    scored_paths = []
    
    for record in raw_results:
        path = record['p']
        features = extract_features(path)
        
        # Automatically use the dynamic column headers
        df_features = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        
        success_prob = model.predict_proba(df_features)[0][1] 
        
        scored_paths.append({
            "path": path,
            "features": features,
            "success_probability": round(success_prob * 100, 2)
        })
        
    scored_paths.sort(key=lambda x: x["success_probability"], reverse=True)
    
    return scored_paths