"""Ingestor module

Extracts SharpHound zip files, parses JSON data, and loads nodes and relationships into Neo4j.

Functions
---------
- `extract_zip(zip_path: str, extract_to: str) -> str`
- `load_data(extract_dir: str, db_manager) -> None`
"""

import os
import zipfile
import json
from typing import Dict, Any
from core.database import DatabaseManager


def extract_zip(zip_path: str, extract_to: str) -> str:
    """Extract the SharpHound zip to a directory and return the extraction path."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_to)
    return extract_to


def load_data(extract_dir: str, db: DatabaseManager) -> None:
    """Parse extracted SharpHound JSON files and load them into Neo4j using `DatabaseManager`.
    
    Expected JSON structure from SharpHound:
    - *Users.json: Array of user objects with properties like ObjectIdentifier, samaccountname, etc.
    - *Computers.json: Array of computer objects
    - *Groups.json: Array of group objects
    - Relationship files (e.g., LocalAdmin.json, MemberOf.json, etc.):
      Array of objects with SourceObjectIdentifier and TargetObjectIdentifier
    """
    # Define node file suffixes and their corresponding labels
    node_suffixes = {
        '_users.json': 'User',
        '_computers.json': 'Computer',
        '_groups.json': 'Group'
    }
    
    # Process all JSON files in the extract directory
    print("[+] Processing JSON files...")
    for filename in os.listdir(extract_dir):
        if not filename.endswith('.json'):
            continue
            
        filepath = os.path.join(extract_dir, filename)
        
        # Check if this file is a node file (by suffix)
        node_label = None
        for suffix, label in node_suffixes.items():
            if filename.endswith(suffix):
                node_label = label
                break
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[!] Failed to parse {filename}: {e}")
                continue
        # Handle SharpHound's JSON structure: { "data": [...] }
        if isinstance(data, dict) and 'data' in data:
            data = data['data']
        
        if not isinstance(data, list):
            print(f"[!] {filename} does not contain a JSON array")
            continue
            
        if node_label:
            # Process as node file (Users, Computers, Groups)
            print(f"[+] Processing {filename} as node type {node_label}...")
            for obj in data:
                if not isinstance(obj, dict):
                    continue
                    
                # Use ObjectIdentifier as unique node ID, fallback to ObjectSid
                node_id = obj.get('ObjectIdentifier') or obj.get('ObjectSid')
                if not node_id:
                    continue
                    
                # Prepare properties (exclude identifier fields to avoid duplication)
                # Only include primitive types (string, number, boolean) and arrays of primitives
                props = {}
                for k, v in obj.items():
                    if k in ['ObjectIdentifier', 'ObjectSid'] or v is None:
                        continue
                    if isinstance(v, (str, int, float, bool)):
                        props[k] = v
                    elif isinstance(v, list):
                        # Check if all elements are primitive
                        if all(isinstance(elem, (str, int, float, bool)) for elem in v):
                            props[k] = v
                        # else skip the list
                    elif isinstance(v, dict):
                        # Flatten Properties dictionary if present (e.g., name, domain, etc.)
                        if k == 'Properties':
                            for pk, pv in v.items():
                                if isinstance(pv, (str, int, float, bool)):
                                    props[pk] = pv
                                elif isinstance(pv, list):
                                    if all(isinstance(elem, (str, int, float, bool)) for elem in pv):
                                        props[pk] = pv
                
                # Create or merge node
                query = f"""
                MERGE (n:{node_label} {{objectid: $node_id}})
                ON CREATE SET n += $props
                ON MATCH SET n += $props
                """
                db.run_query(query, {'node_id': node_id, 'props': props})
        else:
            # Process as relationship file
            # Derive relationship type from filename (e.g., 20260613062313_domains.json -> DOMAINS)
            # Remove the .json extension and any timestamp prefix (numeric followed by underscore)
            base = filename.replace('.json', '')
            # Split by '_' and take the last part as the relationship type name
            parts = base.split('_')
            rel_type = parts[-1].upper() if len(parts) > 1 else base.upper()
            
            print(f"[+] Processing {filename} as relationship type {rel_type}...")
            for rel in data:
                if not isinstance(rel, dict):
                    continue
                    
                source_id = rel.get('SourceObjectIdentifier')
                target_id = rel.get('TargetObjectIdentifier')
                if not source_id or not target_id:
                    continue
                    
                # Create or merge relationship
                query = f"""
                MATCH (a {{objectid: $source_id}})
                MATCH (b {{objectid: $target_id}})
                MERGE (a)-[r:{rel_type}]->(b)
                """
                db.run_query(query, {'source_id': source_id, 'target_id': target_id})


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
