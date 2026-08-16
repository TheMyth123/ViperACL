import os
import yaml
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

class DatabaseManager:
    def __init__(self, uri=None, username=None, password=None, database=None, config_path=None):
        """Load Neo4j connection parameters from config.yaml with env overrides."""
        config_path = config_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "config.yaml"
        )
        cfg = {}

        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    cfg = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                raise RuntimeError(f"Error parsing config.yaml: {e}")

        neo4j_cfg = cfg.get("neo4j", {})

        self.uri = uri or os.getenv("VIPERACL_NEO4J_URI") or neo4j_cfg.get("uri") or "bolt://127.0.0.1:7687"
        self.user = username or os.getenv("VIPERACL_NEO4J_USERNAME") or neo4j_cfg.get("username") or "neo4j"
        self.password = password or os.getenv("VIPERACL_NEO4J_PASSWORD") or neo4j_cfg.get("password") or "viperacl"
        self.database = database or os.getenv("VIPERACL_NEO4J_DATABASE") or neo4j_cfg.get("database") or "neo4j"

        if not all([self.uri, self.user, self.password, self.database]):
            raise RuntimeError("Incomplete Neo4j connection settings")

        self.driver = None

    def connect(self):
        """Establishes a connection to the Neo4j instance."""
        try:
            # Modern driver initialization
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # New in modern drivers: Verify the connection immediately
            self.driver.verify_connectivity()
            print("[+] Successfully connected to Neo4j database!")
            # Ensure a few name indexes exist to make MATCH {name:..} queries fast on large graphs.
            try:
                with self.driver.session(database=self.database) as session:
                    # Create indexes for common labels used by the ingestor/importer.
                    session.run("CREATE INDEX IF NOT EXISTS FOR (n:Base) ON (n.name)")
                    session.run("CREATE INDEX IF NOT EXISTS FOR (n:User) ON (n.name)")
                    session.run("CREATE INDEX IF NOT EXISTS FOR (n:Group) ON (n.name)")
                    session.run("CREATE INDEX IF NOT EXISTS FOR (n:Computer) ON (n.name)")
                    session.run("CREATE INDEX IF NOT EXISTS FOR (n:Base) ON (n.project_id)")
            except Exception:
                # Non-fatal: if index creation fails, continue — queries will still run.
                pass
            return True
        except AuthError:
            print("[!] Authentication failed. Check your username and password.")
        except ServiceUnavailable:
            print(f"[!] Could not connect to the database at {self.uri}. Is Neo4j running?")
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")
        return False

    def close(self):
        """Closes the driver instance."""
        if self.driver:
            self.driver.close()

    def run_query(self, query, parameters=None):
        """Runs a Cypher query and returns the results as a list of dictionaries."""
        if not self.driver:
            print("[!] Driver not initialized. Call connect() first.")
            return []
        
        # Use a session to run the query, compatible with driver versions lacking execute_query
        with self.driver.session(database=self.database) as session:
            result = session.run(query, parameters or {})
            records = [record.data() for record in result]
            return records

    def get_project_snapshot(self, project_id=None):
        """Returns node and relationship counts for a specific project_id (or overall if None)."""
        snapshot = {
            "connected": False,
            "nodes": None,
            "relationships": None,
            "database": self.database,
            "uri": self.uri,
            "project_id": project_id
        }

        if not self.driver:
            return snapshot

        try:
            snapshot["connected"] = True
            if project_id:
                node_res = self.run_query("MATCH (n {project_id: $pid}) RETURN count(n) AS node_count", {"pid": project_id})
                rel_res = self.run_query("MATCH ()-[r {project_id: $pid}]->() RETURN count(r) AS rel_count", {"pid": project_id})
            else:
                node_res = self.run_query("MATCH (n) RETURN count(n) AS node_count")
                rel_res = self.run_query("MATCH ()-[r]->() RETURN count(r) AS rel_count")

            if node_res:
                snapshot["nodes"] = node_res[0].get("node_count", 0)
            if rel_res:
                snapshot["relationships"] = rel_res[0].get("rel_count", 0)
        except Exception as e:
            print(f"[!] Snapshot error: {e}")
            snapshot["connected"] = False

        return snapshot