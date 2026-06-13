from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
from utils.config_loader import load_config

class DatabaseManager:
    def __init__(self):
        config = load_config()
        neo4j_config = config.get('neo4j', {})
        self.uri = neo4j_config.get('uri')
        self.user = neo4j_config.get('user')
        self.password = neo4j_config.get('password')
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
        
        results = []
        with self.driver.session(database="neo4j") as session:
            result = session.run(query, parameters or {})
            for record in result:
                results.append(dict(record))
        return results