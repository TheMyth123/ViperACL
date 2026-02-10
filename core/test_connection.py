from database import DatabaseManager

# Change these to match your Neo4j settings
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "bloodhoundcommunityedition" # Your actual password

db = DatabaseManager(NEO4J_URI, NEO4J_USER, NEO4J_PASS)

if db.connect():
    # Let's count how many Users are in your BloodHound database
    query = "MATCH (u:User) RETURN count(u) as userCount"
    results = db.run_query(query)
    
    if results:
        count = results[0]["userCount"]
        print(f"[*] Found {count} Users in the BloodHound database.")
    else:
        print("[?] Connected, but no users found. Have you imported data yet?")
    
    db.close()