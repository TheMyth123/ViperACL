import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from utils.database import DatabaseManager  # Assuming database.py is in the same directory or adjust import
from core.ingestor.parser import SharpHoundIngestor

def main():
    # 1. Connect to DB
    db = DatabaseManager()
    if not db.connect():
        sys.exit(1)

    # 2. Initialize Ingestor
    ingestor = SharpHoundIngestor(db)
    
    # Optional: Wipe old data before new ingestion
    ingestor.clear_database()

    # 3. Run Ingestion (Point to your SharpHound zip)
    zip_target = "dev/20260702105422_VIPERTECH.zip"
    ingestor.ingest_zip(zip_target)

    # 4. Close DB
    db.close()

if __name__ == "__main__":
    main()