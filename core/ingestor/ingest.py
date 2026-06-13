"""Ingestor module

Extracts SharpHound zip files, parses CSV/JSON data, and loads nodes and relationships into Neo4j.

Functions
---------
- `extract_zip(zip_path: str, extract_to: str) -> str`
- `load_data(extract_dir: str, db_manager) -> None`
"""
import os
import zipfile
from typing import List
from core.database import DatabaseManager

def extract_zip(zip_path: str, extract_to: str) -> str:
    """Extract the SharpHound zip to a directory and return the extraction path."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_to)
    return extract_to

def load_data(extract_dir: str, db: DatabaseManager) -> None:
    """Parse extracted files and load them into Neo4j using `DatabaseManager`.

    This is a stub – actual parsing logic will be implemented later.
    """
    # Placeholder for parsing CSV/JSON files and creating nodes/relationships
    pass

def ingest_zip(zip_path: str) -> None:
    """High‑level helper that creates a `DatabaseManager`, extracts the zip, and loads data.
    """
    db = DatabaseManager()
    if not db.connect():
        raise ConnectionError("Failed to connect to Neo4j")
    extract_dir = os.path.join(os.path.dirname(zip_path), "extracted")
    extract_zip(zip_path, extract_dir)
    load_data(extract_dir, db)
    db.close()
