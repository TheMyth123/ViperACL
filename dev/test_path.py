import sys
import os
# This forces Python to add your root ViperACL folder to its search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database import DatabaseManager
from core.pathfinder.pathfinder import Pathfinder

db = DatabaseManager()
if db.connect():
    pf = Pathfinder(db)
    
    # Try to find a path from a user you control to "DOMAIN ADMINS@DOMAIN.LOCAL"
    # Make sure to use the EXACT name format seen in BloodHound (all caps usually)
    source = "WLEY@INLANEFREIGHT.LOCAL"
    target = "ADUNN@INLANEFREIGHT.LOCAL"
    
    results = pf.find_best_path(source, target)
    
    if results:
        record = results[0]
        path = record['p']
        weight = record['pathWeight']
        # Determine number of steps (relationships) in the path list
        steps = (len(path) - 1) // 2
        print(f"[+] Found a path with {steps} steps and total weight {weight}!")
        # Iterate over the path list: node, rel, node, rel, ...
        for i in range(0, len(path) - 2, 2):
            start_node = path[i]['name']
            rel_type = path[i + 1]
            end_node = path[i + 2]['name']
            print(f"  {start_node} --[{rel_type}]--> {end_node}")
    else:
        print("[-] No exploitable ACL path found between those two points.")
    
    db.close()