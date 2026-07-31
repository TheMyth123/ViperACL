def run_fasttrack(db, source_name, target_name):
    """
    Viper FastTrack Engine: Finds the path with the absolute fewest hops, 
    ignoring relationship weights.
    """
    query = """
    // Node definitions moved directly into shortestPath function
    MATCH p = shortestPath((source {name: $source_name})-[*1..15]->(target {name: $target_name}))
    RETURN p, length(p) AS hops
    LIMIT 1
    """
    
    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper()
    }
    
    return db.run_query(query, parameters=params)