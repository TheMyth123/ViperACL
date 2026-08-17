# core/pathfinder/tactical.py

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

def run_tactical(db, source_name, target_name, max_hops=15):
    """
    Viper Tactical Engine: Finds the lowest-cost path using Cypher REDUCE.
    """
    # Get relationship types present in the DB and intersect with our cost map
    try:
        rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get('rel') for row in rel_rows if row.get('rel')}
    except Exception:
        present_rels = set()

    allowed_rels = [r for r in COST_MAP.keys() if r in present_rels]

    # If none of our expected relationship types are present, bail out early.
    if not allowed_rels:
        return []

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
        "weight_map": COST_MAP
    }

    # Step 1: determine minimum hop length to tightly bound the search space
    q_short = f"""
    MATCH p = shortestPath((source {{name: $source_name}})-[:{rel_pattern}*1..{hops_limit}]->(target {{name: $target_name}}))
    RETURN length(p) AS min_hops
    """
    short_rows = db.run_query(q_short, parameters=params)
    if not short_rows or not short_rows[0].get("min_hops"):
        return []

    min_hops = short_rows[0]["min_hops"]
    search_depth = min(min_hops + 2, hops_limit)

    # Step 2: find the lowest-cost path within the optimized depth bound
    query = f"""
    MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
    MATCH p = (source)-[:{rel_pattern}*1..{search_depth}]->(target)
    WITH p, reduce(total = 0, r IN relationships(p) | total + $weight_map[type(r)]) AS pathWeight
    RETURN p, pathWeight
    ORDER BY pathWeight ASC, length(p) ASC
    LIMIT 1
    """

    return db.run_query(query, parameters=params)