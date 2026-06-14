import logging
import sys
from pathlib import Path

import yaml
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

# Setup basic logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def load_config(config_path: Path):
    """Load Neo4j connection details from a YAML config file.

    Expected structure:
    ```yaml
    neo4j:
      uri: "bolt://localhost:7687"
      username: "neo4j"
      password: "secret"
    ```
    """
    if not config_path.is_file():
        logger.error("Config file %s does not exist", config_path)
        sys.exit(1)
    try:
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f)
        neo4j_cfg = cfg.get('neo4j', {})
        return neo4j_cfg.get('uri'), neo4j_cfg.get('username'), neo4j_cfg.get('password')
    except Exception as e:
        logger.exception("Failed to parse config file: %s", e)
        sys.exit(1)

def clear_database(uri: str, user: str, password: str):
    """Delete all nodes and relationships safely.
    Returns the number of deleted nodes and relationships.
    """
    driver = None
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            # Count before deletion (without APOC)
            node_result = session.run("MATCH (n) RETURN count(n) AS nodes")
            rel_result = session.run("MATCH ()-[r]->() RETURN count(r) AS rels")
            node_count = node_result.single()["nodes"]
            rel_count = rel_result.single()["rels"]
            logger.info("Current DB size: %d nodes, %d relationships", node_count, rel_count)

            # Delete all relationships first, then nodes
            result = session.run("MATCH (n) DETACH DELETE n")
            # The result summary gives counters
            summary = result.consume()
            deleted_nodes = summary.counters.nodes_deleted
            deleted_rels = summary.counters.relationships_deleted
            logger.info("Deleted %d nodes and %d relationships", deleted_nodes, deleted_rels)
            return deleted_nodes, deleted_rels
    except Neo4jError as e:
        logger.error("Neo4j error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        sys.exit(1)
    finally:
        if driver:
            driver.close()

def main():
    config_path = Path(__file__).parent.parent / "config.yaml"
    uri, user, password = load_config(config_path)
    if not all([uri, user, password]):
        logger.error("Missing Neo4j configuration in %s", config_path)
        sys.exit(1)
    clear_database(uri, user, password)

if __name__ == "__main__":
    main()
