#!/usr/bin/env python3
"""
Clear Neo4j database.

This script removes all nodes and relationships from the Neo4j instance
configured in `config.yaml`. It is useful before re‑importing data with
the official BloodHound/SharpHound tools to ensure a clean graph.
"""

import sys
import os

# Ensure the project root (one level up from dev) is on the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager

def clear_db():
    db = DatabaseManager()
    if not db.connect():
        sys.exit(1)
    try:
        db.run_query("MATCH (n) DETACH DELETE n")
        print("[+] Neo4j database cleared successfully.")
    except Exception as e:
        print(f"[!] Failed to clear Neo4j database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    clear_db()
