import json
import zipfile
import os

class SharpHoundIngestor:
    def __init__(self, db_manager):
        self.db = db_manager

    def clear_database(self):
        print("[*] Clearing existing Neo4j database...")
        self.db.run_query("MATCH (n) DETACH DELETE n")
        print("[+] Database cleared.")

    def ingest_zip(self, zip_path):
        if not os.path.exists(zip_path):
            print(f"[!] Error: File {zip_path} not found.")
            return

        print(f"[*] Opening SharpHound archive: {zip_path}")
        with zipfile.ZipFile(zip_path, 'r') as z:
            for filename in z.namelist():
                if filename.endswith('.json'):
                    base_name = os.path.basename(filename).lower()
                    
                    # Map files cleanly to target domain types
                    if "user" in base_name:
                        node_type = "User"
                    elif "computer" in base_name:
                        node_type = "Computer"
                    elif "group" in base_name:
                        node_type = "Group"
                    elif "gpo" in base_name:
                        node_type = "GPO"
                    elif "ou" in base_name:
                        node_type = "OU"
                    elif "domain" in base_name:
                        node_type = "Domain"
                    elif "container" in base_name:
                        node_type = "Container"
                    else:
                        continue

                    with z.open(filename) as f:
                        print(f"[*] Parsing {filename} as type ':{node_type}'...")
                        data = json.load(f)
                        items = data.get('data', [])
                        
                        if not items:
                            continue
                            
                        self._process_items(node_type, items)
        
        print("[+] Ingestion complete! The database graph is now aligned.")

    def _process_items(self, node_type, items):
        nodes = []
        edges = []

        for item in items:
            obj_id = item.get('ObjectIdentifier')
            props = item.get('Properties', {})
            # Keep naming casing standard to match your pathfinder expectations
            name = props.get('name') or item.get('Name') or 'UNKNOWN'
            
            if not obj_id:
                continue

            nodes.append({'id': obj_id, 'name': name.upper()})

            # Inbound Access Control Lists
            for ace in item.get('Aces', []):
                principal = ace.get('PrincipalSID')
                right = ace.get('RightName')
                if principal and right:
                    edges.append({'source': principal, 'target': obj_id, 'rel': right})

            # Group Memberships
            for member in item.get('Members', []):
                member_id = member.get('ObjectIdentifier')
                if member_id:
                    edges.append({'source': member_id, 'target': obj_id, 'rel': 'MemberOf'})

        # --- OPTIMIZED BATCH WRITE ---
        
        # 1. Merge uniquely on the base objectid to prevent object inflation
        if nodes:
            query_nodes = f"""
            UNWIND $batch AS data
            MERGE (n:Base {{objectid: data.id}})
            SET n.name = data.name, n:`{node_type}`
            """
            self.db.run_query(query_nodes, {"batch": nodes})
            print(f"  [+] Synced {len(nodes)} elements under label ':{node_type}'")

        # 2. Dynamic relationship creation with fallbacks for unresolved SIDs
        if edges:
            rel_groups = {}
            for e in edges:
                rel_groups.setdefault(e['rel'], []).append(e)
            
            for rel_type, batch in rel_groups.items():
                clean_rel = "".join(c for c in rel_type if c.isalnum())
                if not clean_rel: 
                    continue

                # MERGE ensures that missing/unresolved principal SIDs are created 
                # gracefully on-the-fly rather than discarding the entire path line
                query_edges = f"""
                UNWIND $batch AS data
                MERGE (source:Base {{objectid: data.source}})
                MERGE (target:Base {{objectid: data.target}})
                MERGE (source)-[:{clean_rel}]->(target)
                """
                self.db.run_query(query_edges, {"batch": batch})
            print(f"  [+] Structuralized {len(edges)} attack relationships.")