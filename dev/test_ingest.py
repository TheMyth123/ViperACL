import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from utils.database import DatabaseManager
from core.ingestor.parser import SharpHoundIngestor
from core.projects import ProjectManager

def main():
    print("==================================================")
    print(" VIPERACL MULTI-PROJECT INGESTION TEST")
    print("==================================================")

    # 1. Connect to DB & ProjectManager
    db = DatabaseManager()
    if not db.connect():
        sys.exit(1)

    project_mgr = ProjectManager()

    # 2. Project 1: Primary Target (Latest ZIP)
    p1_id = "proj_20260702105422_VIPERTECH"
    p1_name = "VIPERTECH Primary Domain"
    p1_zip = "dev/202607002052333_VIPERTECH.zip"

    ingestor1 = SharpHoundIngestor(db, project_id=p1_id)
    ingestor1.clear_database(project_id=p1_id)
    ingestor1.ingest_zip(p1_zip, project_id=p1_id)
    snap1 = db.get_project_snapshot(p1_id)
    project_mgr.register_project(p1_id, p1_name, p1_zip, snap1.get("nodes", 0), snap1.get("relationships", 0))

    # 3. Project 2: Secondary Target
    p2_id = "proj_20260702104256_VIPERTECH"
    p2_name = "VIPERTECH Secondary Audit"
    p2_zip = "dev/20260702104256_VIPERTECH.zip"

    ingestor2 = SharpHoundIngestor(db, project_id=p2_id)
    ingestor2.clear_database(project_id=p2_id)
    ingestor2.ingest_zip(p2_zip, project_id=p2_id)
    snap2 = db.get_project_snapshot(p2_id)
    project_mgr.register_project(p2_id, p2_name, p2_zip, snap2.get("nodes", 0), snap2.get("relationships", 0))

    # 4. Set Project 1 as default active project
    project_mgr.set_active_project(p1_id)

    # 5. Print Multi-Project Verification Results
    overall_snap = db.get_project_snapshot()

    print("\n--------------------------------------------------")
    print(" VERIFICATION & ISOLATED METRICS SUMMARY")
    print("--------------------------------------------------")
    print(f"Project 1 [{p1_id}]: {snap1.get('nodes')} nodes, {snap1.get('relationships')} relationships")
    print(f"Project 2 [{p2_id}]: {snap2.get('nodes')} nodes, {snap2.get('relationships')} relationships")
    print(f"Combined Database Total: {overall_snap.get('nodes')} nodes, {overall_snap.get('relationships')} relationships")
    print("Active Project ID:", project_mgr.get_active_project_id())
    print("==================================================")

    db.close()

if __name__ == "__main__":
    main()