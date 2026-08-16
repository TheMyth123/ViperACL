import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import DatabaseManager

db = DatabaseManager()

if db.connect():
    query = "MATCH (u:User) RETURN count(u) as userCount"
    results = db.run_query(query)
    
    if results:
        count = results[0]["userCount"]
        print(f"[*] Found {count} Users in the ViperACL database.")
    else:
        print("[?] Connected, but no users found. Have you imported data yet?")
    
    db.close()