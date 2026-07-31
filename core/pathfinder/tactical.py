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

def run_tactical(db, source_name, target_name):
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

    query = f"""
    MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
    MATCH p = (source)-[:{rel_pattern}*1..5]->(target)
    WITH p, reduce(total = 0, r IN relationships(p) | total + $weight_map[type(r)]) AS pathWeight
    RETURN p, pathWeight
    ORDER BY pathWeight ASC, length(p) ASC
    LIMIT 1
    """

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
        "weight_map": COST_MAP
    }

    return db.run_query(query, parameters=params)