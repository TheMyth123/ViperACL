import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.pathfinder.find_paths import Pathfinder

db = DatabaseManager("bolt://localhost:7687", "neo4j", "bloodhoundcommunityedition")
if db.connect():
    pf = Pathfinder(db)
    
    # Try to find a path from a user you control to "DOMAIN ADMINS@DOMAIN.LOCAL"
    # Make sure to use the EXACT name format seen in BloodHound (all caps usually)
    source = "WLEY@INLANEFREIGHT.LOCAL"
    target = "ADUNN@INLANEFREIGHT.LOCAL"
    
    results = pf.find_best_path(source, target)
    
    if results:
        path = results[0]['p']
        weight = results[0]['pathWeight']
        print(f"[+] Found a path with {len(path.relationships)} steps and total weight {weight}!")
        for rel in path.relationships:
            # This prints: (User) -[AdminTo]-> (Computer)
            start_node = rel.start_node['name']
            end_node = rel.end_node['name']
            print(f"  {start_node} --[{rel.type}]--> {end_node}")
    else:
        print("[-] No exploitable ACL path found between those two points.")
    
    db.close()