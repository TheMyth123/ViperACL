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
    query = """
    // Node definitions are now directly inside the path match
    MATCH p = (source {name: $source_name})-[*1..15]->(target {name: $target_name})
    WHERE all(r IN relationships(p) WHERE type(r) IN keys($weight_map))
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