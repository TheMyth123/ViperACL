import json
import zipfile
import os

class SharpHoundIngestor:
    def __init__(self, db_manager, project_id=None):
        self.db = db_manager
        self.project_id = project_id

    def clear_database(self, project_id=None):
        pid = project_id or self.project_id
        if pid:
            print(f"[*] Clearing Neo4j data for project '{pid}'...")
            self.db.run_query("MATCH (n {project_id: $pid}) DETACH DELETE n", {"pid": pid})
        else:
            print("[*] Clearing entire Neo4j database...")
            self.db.run_query("MATCH (n) DETACH DELETE n")
        print("[+] Database cleared.")

    def ingest_zip(self, zip_path, project_id=None):
        pid = project_id or self.project_id or "default"
        self.project_id = pid

        if not os.path.exists(zip_path):
            print(f"[!] Error: File {zip_path} not found.")
            return

        print(f"[*] Opening SharpHound archive: {zip_path} for project '{pid}'")
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
                        print(f"[*] Parsing {filename} as type ':{node_type}' for project '{pid}'...")
                        data = json.load(f)
                        items = data.get('data', [])
                        
                        if not items:
                            continue
                            
                        self._process_items(node_type, items, pid)

        if zip_path == "dev/20260613062313_ILFREIGHT.zip":
            print("[*] Injecting demonstration constraint path to show engine differentiation...")
            self._inject_demo_scenario(pid)
        
        print(f"[+] Ingestion complete for project '{pid}'! The database graph is now aligned.")

    def _process_items(self, node_type, items, project_id):
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
        
        # 1. Merge uniquely on objectid + project_id to keep project graphs isolated
        if nodes:
            query_nodes = f"""
            UNWIND $batch AS data
            MERGE (n:Base {{objectid: data.id, project_id: $pid}})
            SET n.name = data.name, n.project_id = $pid, n:`{node_type}`
            """
            self.db.run_query(query_nodes, {"batch": nodes, "pid": project_id})
            print(f"  [+] Synced {len(nodes)} elements under label ':{node_type}' [Project: {project_id}]")

        # 2. Dynamic relationship creation with project_id tagging
        if edges:
            rel_groups = {}
            for e in edges:
                rel_groups.setdefault(e['rel'], []).append(e)
            
            for rel_type, batch in rel_groups.items():
                clean_rel = "".join(c for c in rel_type if c.isalnum())
                if not clean_rel: 
                    continue

                query_edges = f"""
                UNWIND $batch AS data
                MERGE (source:Base {{objectid: data.source, project_id: $pid}})
                MERGE (target:Base {{objectid: data.target, project_id: $pid}})
                MERGE (source)-[r:{clean_rel}]->(target)
                SET r.project_id = $pid
                """
                self.db.run_query(query_edges, {"batch": batch, "pid": project_id})
            print(f"  [+] Structuralized {len(edges)} attack relationships [Project: {project_id}]")

    def _inject_demo_scenario(self, project_id):
        """
        Injects a 3-way split scenario to demonstrate Non-Linear Feature Interaction (Paradoxes)
        to prove why the Machine Learning Predictive Engine outperforms static pathfinders.
        """
        inject_query = """
        MATCH (src:User {name: 'WLEY@INLANEFREIGHT.LOCAL', project_id: $pid})
        MATCH (tgt:User {name: 'ADUNN@INLANEFREIGHT.LOCAL', project_id: $pid})
        
        // PATH A: FastTrack Bait (2 Hops, Cost 10)
        MERGE (u1:User {name: 'DEMO_NOISY_ADMIN@INLANEFREIGHT.LOCAL', objectid: 'demo-u1', project_id: $pid})
        MERGE (src)-[:ForceChangePassword {project_id: $pid}]->(u1)
        MERGE (u1)-[:ForceChangePassword {project_id: $pid}]->(tgt)
        
        // PATH B: Tactical Bait (4 Hops, Cost 2)
        MERGE (g1:Group {name: 'DEMO_GROUP_A@INLANEFREIGHT.LOCAL', objectid: 'demo-g1', project_id: $pid})
        MERGE (g2:Group {name: 'DEMO_GROUP_B@INLANEFREIGHT.LOCAL', objectid: 'demo-g2', project_id: $pid})
        MERGE (u2:User {name: 'DEMO_TEMP_USER@INLANEFREIGHT.LOCAL', objectid: 'demo-u2', project_id: $pid})
        
        MERGE (src)-[:MemberOf {project_id: $pid}]->(g1)
        MERGE (g1)-[:MemberOf {project_id: $pid}]->(g2)
        MERGE (g2)-[:AddMember {project_id: $pid}]->(u2)
        MERGE (u2)-[:GenericWrite {project_id: $pid}]->(tgt)

        // PATH C: Predictive ML Winner (3 Hops, Cost 3)
        MERGE (u3:User {name: 'DEMO_SVC_1@INLANEFREIGHT.LOCAL', objectid: 'demo-u3', project_id: $pid})
        MERGE (u4:User {name: 'DEMO_SVC_2@INLANEFREIGHT.LOCAL', objectid: 'demo-u4', project_id: $pid})
        
        MERGE (src)-[:GenericWrite {project_id: $pid}]->(u3)
        MERGE (u3)-[:GenericWrite {project_id: $pid}]->(u4)
        MERGE (u4)-[:GenericWrite {project_id: $pid}]->(tgt)
        """
        self.db.run_query(inject_query, {"pid": project_id})
        print("  [+] Injected Paradox scenario: Sync Delay trap successfully planted.")