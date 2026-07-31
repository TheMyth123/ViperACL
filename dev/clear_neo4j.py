import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database import DatabaseManager

# Setup basic logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def clear_database(db: DatabaseManager):
    """Delete all nodes and relationships safely.
    Returns the number of deleted nodes and relationships.
    """
    try:
        if not db.connect():
            sys.exit(1)

        node_result = db.run_query("MATCH (n) RETURN count(n) AS nodes")
        rel_result = db.run_query("MATCH ()-[r]->() RETURN count(r) AS rels")
        node_count = node_result[0]["nodes"] if node_result else 0
        rel_count = rel_result[0]["rels"] if rel_result else 0
        logger.info("Current DB size: %d nodes, %d relationships", node_count, rel_count)

        db.run_query("MATCH (n) DETACH DELETE n")
        logger.info("Deleted all nodes and relationships")
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        sys.exit(1)
    finally:
        db.close()

def main():
    db = DatabaseManager()
    clear_database(db)

if __name__ == "__main__":
    main()
