import logging
import sys
import os

# Ensure project root is in sys.path for imports
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.database import DatabaseManager
from core.ingestor.ingestor import SharpHoundIngestor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Adjust the path to your SharpHound ZIP file
    zip_path = "dev/20260613062313_ILFREIGHT.zip"
    db_manager = DatabaseManager()
    if not db_manager.connect():
        logger.error("Could not connect to Neo4j. Exiting.")
        return
    try:
        ingestor = SharpHoundIngestor(db_manager)
        ingestor.ingest_zip(zip_path)
        logger.info("Ingestion completed successfully.")
    finally:
        db_manager.close()

if __name__ == "__main__":
    main()
