#!/usr/bin/env python3
"""
Test script for the SharpHound ingestor.
Hardcodes the path to a local SharpHound ZIP file to validate the ingestion pipeline.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from core.ingestor.ingest import ingest_zip

if __name__ == "__main__":
    # Hardcoded path to the local SharpHound ZIP file
    # The ZIP file is located in dev/ relative to the project root
    zip_path = os.path.join(os.path.dirname(__file__), '..', '20260613062313_ILFREIGHT.zip')
    # Make sure the path is absolute for reliability
    zip_path = os.path.abspath(zip_path)
    
    if not os.path.exists(zip_path):
        print(f"[!] ZIP file not found at: {zip_path}")
        sys.exit(1)
        
    print(f"[+] Starting ingestion of SharpHound ZIP: {zip_path}")
    try:
        ingest_zip(zip_path)
        print("[+] Ingestion completed successfully!")
    except Exception as e:
        print(f"[!] Ingestion failed: {e}")
        sys.exit(1)