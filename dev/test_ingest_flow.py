"""Tests for SharpHound page, binary download endpoint, archive upload/inspection, and execution."""

import os
from pathlib import Path
from fastapi.testclient import TestClient

from core.projects import ProjectManager
from web.app import create_app


def test_sharphound_page_and_download():
    app = create_app()
    client = TestClient(app)

    # 1. Test /sharphound page render
    res = client.get("/sharphound")
    assert res.status_code == 200
    assert "SharpHound Collector" in res.text
    assert "SharpHound.exe -c All --zipfilename" in res.text

    # 2. Test download endpoint with real SharpHound.exe in data/tools/
    res_dl = client.get("/api/tools/sharphound/download")
    assert res_dl.status_code == 200
    assert res_dl.headers.get("content-type") == "application/octet-stream"
    assert len(res_dl.content) > 1000000


def test_upload_inspect_and_execute_ingest():
    app = create_app()
    client = TestClient(app)

    # Ensure an active project exists
    mgr = ProjectManager()
    projects = mgr.list_projects()
    if not projects:
        create_res = client.post("/api/projects/create", json={"name": "Test Ingest Project"})
        assert create_res.status_code == 200
        project_id = create_res.json()["project"]["project_id"]
    else:
        project_id = projects[0]["project_id"]
        client.post("/api/projects/select", json={"project_id": project_id})

    # Pick a sample zip from dev/
    sample_zip = Path("dev/20260702105422_VIPERTECH.zip")
    assert sample_zip.exists(), "Sample zip not found in dev/"

    # Test Upload & Inspect
    with open(sample_zip, "rb") as f:
        res_upload = client.post(
            "/api/ingest/upload",
            files={"file": ("20260702105422_VIPERTECH.zip", f, "application/zip")},
            data={"project_id": project_id},
        )
    assert res_upload.status_code == 200
    data = res_upload.json()
    assert data["status"] == "ok"
    assert "staged_path" in data
    assert data["metadata"]["valid"] is True
    assert data["metadata"]["counts"]["users"] > 0
    assert data["metadata"]["counts"]["computers"] > 0

    staged_path = data["staged_path"]

    # Test Ingestion Execution
    res_exec = client.post(
        "/api/ingest/execute",
        json={"staged_path": staged_path, "project_id": project_id, "clear_database": True},
    )
    assert res_exec.status_code == 200
    exec_data = res_exec.json()
    assert exec_data["status"] == "ok"
    assert exec_data["snapshot"]["nodes"] > 0
    assert exec_data["snapshot"]["relationships"] > 0


if __name__ == "__main__":
    import pytest
    pytest.main(["-v", __file__])
