import logging
import zipfile
import ijson
from typing import Any, Dict, List
from utils.database import DatabaseManager

# Helper to build relationship Cypher queries (copied from BloodHound importer)
def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Construct a Cypher query to merge an edge between source and target nodes.

    Args:
        source_label: Label of the source node (e.g., 'User').
        target_label: Label of the target node (e.g., 'Group').
        edge_type:   Relationship type (e.g., 'MemberOf').
        edge_props:  String of map properties for the relationship, e.g. '{isacl:false}'.
    """
    return (
        "UNWIND $props AS prop "
        "MERGE (n:Base {objectid: prop.source}) SET n:" + source_label + " "
        "MERGE (m:Base {objectid: prop.target}) SET m:" + target_label + " "
        "MERGE (n)-[r:" + edge_type + " " + edge_props + "]->(m)"
    )

# Helper to build relationship Cypher queries
def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Construct a Cypher query to merge an edge between source and target nodes.

    Args:
        source_label: Label of the source node (e.g., 'User').
        target_label: Label of the target node (e.g., 'Group').
        edge_type:   Relationship type (e.g., 'MemberOf').
        edge_props:  String of map properties for the relationship, e.g. '{isacl:false}'.
    """
    return (
        "UNWIND $props AS prop "
        "MERGE (n:Base {objectid: prop.source}) SET n:" + source_label + " "
        "MERGE (m:Base {objectid: prop.target}) SET m:" + target_label + " "
        "MERGE (n)-[r:" + edge_type + " " + edge_props + "]->(m)"
    )

# Helper to build relationship Cypher queries (copied from bloodhound_import)
def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Construct a Cypher query to merge an edge between source and target nodes.

    Args:
        source_label: Label of the source node (e.g., 'User').
        target_label: Label of the target node (e.g., 'Group').
        edge_type:   Relationship type (e.g., 'MemberOf').
        edge_props:  String of map properties for the relationship, e.g. '{isacl:false}'.
    """
    return (
        "UNWIND $props AS prop "
        "MERGE (n:Base {objectid: prop.source}) SET n:" + source_label + " "
        "MERGE (m:Base {objectid: prop.target}) SET m:" + target_label + " "
        "MERGE (n)-[r:" + edge_type + " " + edge_props + "]->(m)"
    )

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SharpHoundIngestor:
    """Ingests SharpHound data into Neo4j."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.batch_size = 100
        self.batch = []

    def ingest_zip(self, zip_path: str):
        """Processes a SharpHound ZIP file and imports its contents."""
        logger.info(f"Starting ingestion of {zip_path}")
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                for file_info in z.infolist():
                    if file_info.filename.endswith('.json'):
                        logger.info(f"Processing {file_info.filename}")
                        with z.open(file_info) as f:
                            node_type = self._get_node_type_from_filename(file_info.filename)
                            self._process_json_stream(f, node_type)
            self._flush_batch()
        except Exception as e:
            logger.error(f"Failed to process ZIP file: {e}")
            raise

    def _get_node_type_from_filename(self, filename: str) -> str:
        """Maps filename to node type."""
        mapping = {
            "computers.json": "Computer",
            "users.json": "User",
            "groups.json": "Group",
            "domains.json": "Domain",
            "gpos.json": "GPO",
            "ous.json": "OU",
            "containers.json": "Container"
        }
        for key, value in mapping.items():
            if key in filename.lower():
                return value
        return "Base"

    def _process_json_stream(self, file_handle, node_type: str):
        """Streams JSON data and imports into Neo4j, handling UTF-8 BOM."""
        try:
            import io
            # Decode with UTF-8 BOM handling
            text_stream = io.TextIOWrapper(file_handle, encoding='utf-8-sig')
            data = ijson.items(text_stream, 'data.item')
            for item in data:
                self._add_to_batch(item, node_type)
        except Exception as e:
            logger.error(f"Error streaming JSON: {e}")

    def _add_to_batch(self, item: Dict[str, Any], node_type: str):
        """Adds an item to the batch and flushes if full."""
        self.batch.append((item, node_type))
        if len(self.batch) >= self.batch_size:
            self._flush_batch()

    def _flush_batch(self):
        """Flushes the current batch to Neo4j."""
        if not self.batch:
            return
        
        logger.info(f"Flushing batch of {len(self.batch)} items")
        
        # Using UNWIND for batch processing
        # This query is for batching nodes. Relationships need a separate approach.
        # For now, we process items individually to ensure correctness.
        # The UNWIND query below is a placeholder for future batch relationship imports.
        # query = """
        # UNWIND $batch AS item
        # MERGE (n:Base {objectid: item.objectid})
        # SET n:Base
        # SET n += item.properties
        # SET n:LabelPlaceholder
        # """
        # Note: The above query is a simplified batch example.
        # A real implementation would need to handle dynamic labels.
        
        # Process items individually for now to ensure correctness
        # Batching for relationships will be handled separately.
        for item, node_type in self.batch:
            self._import_item(item, node_type)
            
        self.batch = []

    def _import_item(self, item: Dict[str, Any], node_type: str):
        """Imports a single item into Neo4j using Cypher."""
        object_id = item.get("ObjectIdentifier")
        if not object_id:
            return

        # Create node with only the objectid and appropriate label to avoid complex property types
        query = f"""
        MERGE (n:Base {{objectid: $objectid}})
        SET n:{node_type}
        """
        params = {"objectid": object_id}
        try:
            self.db.run_query(query, params)
        except Exception as e:
            logger.error(f"Failed to import item {object_id}: {e}")

        # Process relationships for the imported item
        try:
            # PrimaryGroupSid relationship (User or Computer -> Group)
            if node_type in ("User", "Computer") and item.get("PrimaryGroupSid"):
                rel_query = build_add_edge_query(node_type, "Group", "MemberOf", "{isacl:false}")
                rel_params = {"props": [{"source": object_id, "target": item["PrimaryGroupSid"]}]}
                self.db.run_query(rel_query, rel_params)

            # AllowedToDelegate relationships (User -> Computer)
            if node_type == "User" and item.get("AllowedToDelegate"):
                for entry in item["AllowedToDelegate"]:
                    rel_query = build_add_edge_query("User", "Computer", "AllowedToDelegate", "{isacl:false}")
                    rel_params = {"props": [{"source": object_id, "target": entry["ObjectIdentifier"]}]}
                    self.db.run_query(rel_query, rel_params)

            # Aces (ACL entries) – generic handling
            if item.get("Aces"):
                for ace in item["Aces"]:
                    principal = ace.get("PrincipalSID")
                    principal_type = ace.get("PrincipalType")
                    right = ace.get("RightName")
                    if principal and principal != object_id:
                        rel_query = build_add_edge_query(principal_type, node_type, right, "{isacl:true, isinherited: prop.isinherited}")
                        rel_params = {"props": [{"source": principal, "target": object_id, "isinherited": ace.get("IsInherited", False)}]}
                        self.db.run_query(rel_query, rel_params)

            # SPNTargets for Users (User -> Computer)
            if node_type == "User" and item.get("SPNTargets"):
                for spn in item["SPNTargets"]:
                    rel_query = build_add_edge_query("User", "Computer", "WriteSPN", "{isacl:false, port: prop.port}")
                    rel_params = {"props": [{"source": object_id, "target": spn["ComputerSID"], "port": spn.get("Port")}]}
                    self.db.run_query(rel_query, rel_params)

            # Group members relationship (Member SID -> Group)
            if node_type == "Group" and item.get("Members"):
                for member_sid in item["Members"]:
                    rel_query = build_add_edge_query("Base", "Group", "MemberOf", "{isacl:false}")
                    rel_params = {"props": [{"source": member_sid, "target": object_id}]}
                    self.db.run_query(rel_query, rel_params)
                    
                    # Also create reverse relationship for traversal
                    rev_query = build_add_edge_query("Group", "Base", "MemberOf", "{isacl:false}")
                    rev_params = {"props": [{"source": object_id, "target": member_sid}]}
                    self.db.run_query(rev_query, rev_params)

            # Computer HasSession relationships (User SID -> Computer)
            if node_type == "Computer" and item.get("HasSession"):
                for user_sid in item["HasSession"]:
                    rel_query = build_add_edge_query("User", "Computer", "HasSession", "{isacl:false}")
                    rel_params = {"props": [{"source": user_sid, "target": object_id}]}
                    self.db.run_query(rel_query, rel_params)
                    
                    # Also create reverse relationship for traversal
                    rev_query = build_add_edge_query("Computer", "User", "HasSession", "{isacl:false}")
                    rev_params = {"props": [{"source": object_id, "target": user_sid}]}
                    self.db.run_query(rev_query, rev_params)

        except Exception as e:
            logger.error(f"Failed to import relationships for {object_id}: {e}")
