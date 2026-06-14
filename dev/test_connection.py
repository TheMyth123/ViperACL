import sys
import os
# This forces Python to add your root ViperACL folder to its search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database import DatabaseManager

# Configuration loaded from config.yaml via DatabaseManager
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