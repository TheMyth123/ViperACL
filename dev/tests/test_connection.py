import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager

db = DatabaseManager()

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