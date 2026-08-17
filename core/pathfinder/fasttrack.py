def run_fasttrack(db, source_name, target_name, max_hops=15):
    """
    Viper FastTrack Engine: Finds the path with the absolute fewest hops, 
    ignoring relationship weights.
    """
    hops_limit = max(1, min(int(max_hops), 50))
    query = f"""
    MATCH p = shortestPath((source {{name: $source_name}})-[*1..{hops_limit}]->(target {{name: $target_name}}))
    RETURN p, length(p) AS hops
    LIMIT 1
    """
    
    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper()
    }
    
    return db.run_query(query, parameters=params)