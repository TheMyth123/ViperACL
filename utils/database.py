from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
import os
import yaml

class DatabaseManager:
    def __init__(self):
        """Load Neo4j connection parameters from config.yaml.
        The file must contain a top-level ``neo4j`` mapping with ``uri``, ``username``
        and ``password`` keys. Raises RuntimeError if missing or malformed.
        """
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.yaml")
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
            neo4j_cfg = cfg.get("neo4j")
            if not neo4j_cfg:
                raise RuntimeError("Missing 'neo4j' section in config.yaml")
            self.uri = neo4j_cfg.get("uri")
            self.user = neo4j_cfg.get("username")
            self.password = neo4j_cfg.get("password")
            if not all([self.uri, self.user, self.password]):
                raise RuntimeError("Incomplete Neo4j credentials in config.yaml")
        except FileNotFoundError as e:
            raise RuntimeError(f"Config file not found: {e}")
        except yaml.YAMLError as e:
            raise RuntimeError(f"Error parsing config.yaml: {e}")
        self.driver = None

    def connect(self):
        """Establishes a connection to the Neo4j instance."""
        try:
            # Modern driver initialization
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # New in modern drivers: Verify the connection immediately
            self.driver.verify_connectivity()
            print("[+] Successfully connected to Neo4j database!")
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
        with self.driver.session(database="neo4j") as session:
            result = session.run(query, parameters or {})
            records = [record.data() for record in result]
            return records