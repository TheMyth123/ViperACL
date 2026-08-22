"""
SharpHound Archive Inspector

Validates and extracts pre-ingestion telemetry metrics from SharpHound .zip archives
without loading them into Neo4j.
"""

import json
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional


def format_file_size(size_bytes: int) -> str:
    """Format byte size into human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def inspect_sharphound_zip(zip_path: str | Path) -> Dict[str, Any]:
    """Inspects a SharpHound ZIP archive and extracts high-level domain metrics.

    Returns:
        Dict containing validation status, domain name, object counts, and file size.
    """
    path_obj = Path(zip_path)
    if not path_obj.exists():
        return {
            "valid": False,
            "error": "Archive file does not exist on disk.",
            "counts": {},
            "domains": [],
        }

    file_size = path_obj.stat().st_size
    if file_size == 0:
        return {
            "valid": False,
            "error": "Uploaded archive file is empty (0 bytes).",
            "counts": {},
            "domains": [],
        }

    if not zipfile.is_zipfile(path_obj):
        return {
            "valid": False,
            "error": "File is not a valid ZIP archive format.",
            "counts": {},
            "domains": [],
        }

    counts = {
        "users": 0,
        "computers": 0,
        "groups": 0,
        "gpos": 0,
        "ous": 0,
        "domains": 0,
        "containers": 0,
        "acls": 0,
    }
    domains = set()
    found_sharphound_files = False

    try:
        with zipfile.ZipFile(path_obj, "r") as zf:
            for filename in zf.namelist():
                # Ignore path traversal attempts or macOS metadata
                if filename.startswith("__MACOSX") or filename.startswith("/"):
                    continue

                lower_name = os.path.basename(filename).lower()
                if not lower_name.endswith(".json"):
                    continue

                node_type = None
                if "user" in lower_name:
                    node_type = "users"
                elif "computer" in lower_name:
                    node_type = "computers"
                elif "group" in lower_name:
                    node_type = "groups"
                elif "gpo" in lower_name:
                    node_type = "gpos"
                elif "ou" in lower_name:
                    node_type = "ous"
                elif "domain" in lower_name:
                    node_type = "domains"
                elif "container" in lower_name:
                    node_type = "containers"

                if node_type:
                    found_sharphound_files = True
                    try:
                        with zf.open(filename) as f:
                            data = json.load(f)
                            items = data.get("data", []) if isinstance(data, dict) else []
                            counts[node_type] += len(items)

                            # Extract domain names
                            if node_type == "domains":
                                for d in items:
                                    props = d.get("Properties", {})
                                    name = props.get("name") or d.get("Name")
                                    if name:
                                        domains.add(name.upper())

                            # Extract domain suffix if not found in domain JSON
                            for item in items[:10]:
                                props = item.get("Properties", {})
                                name = props.get("name") or item.get("Name") or ""
                                if "@" in name:
                                    domains.add(name.split("@")[-1].upper())
                                elif "." in name and "\\" in name:
                                    domains.add(name.split("\\")[0].upper())

                            # Count ACEs / ACL edges
                            for item in items:
                                aces = item.get("Aces", [])
                                counts["acls"] += len(aces)
                    except Exception:
                        continue

        if not found_sharphound_files:
            return {
                "valid": False,
                "error": "Archive does not contain standard SharpHound JSON collection files.",
                "counts": counts,
                "domains": list(domains),
            }

        total_nodes = (
            counts["users"]
            + counts["computers"]
            + counts["groups"]
            + counts["gpos"]
            + counts["ous"]
            + counts["domains"]
            + counts["containers"]
        )

        domain_str = list(domains)[0] if domains else "UNKNOWN.LOCAL"

        return {
            "valid": True,
            "filename": path_obj.name,
            "file_size": file_size,
            "file_size_formatted": format_file_size(file_size),
            "primary_domain": domain_str,
            "domains": sorted(list(domains)),
            "counts": counts,
            "total_nodes": total_nodes,
            "total_relationships": counts["acls"],
        }
    except Exception as exc:
        return {
            "valid": False,
            "error": f"Failed to parse SharpHound archive: {exc}",
            "counts": counts,
            "domains": list(domains),
        }
