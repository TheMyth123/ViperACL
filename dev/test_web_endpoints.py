"""Test web page routes and project selection/creation lifecycle."""

import uuid
from fastapi.testclient import TestClient

from core.projects import ProjectManager
from web.app import create_app


def test_web_routes_and_navigation():
    app = create_app()
    client = TestClient(app)

    # 1. Launchpad GET /
    res_home = client.get("/")
    assert res_home.status_code == 200
    assert "Launchpad" in res_home.text

    # 2. Global Logs GET /logs
    res_logs = client.get("/logs")
    assert res_logs.status_code == 200
    assert "Global Logs" in res_logs.text

    # 3. Workspace GET /workspace and /dashboard
    res_ws = client.get("/workspace")
    assert res_ws.status_code == 200
    assert "Tactical Operations Workspace" in res_ws.text

    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert "Tactical Operations Workspace" in res_dash.text

    # 4. Project Creation with Duplicate Rejection
    test_name = f"Audit Alpha {uuid.uuid4().hex[:6]}"
    create_res = client.post("/api/projects/create", json={"name": test_name})
    assert create_res.status_code == 200
    created_id = create_res.json()["project"]["project_id"]
    assert create_res.json()["redirect_url"] == "/workspace"

    # Duplicate rejection (409)
    dup_res = client.post("/api/projects/create", json={"name": test_name.upper()})
    assert dup_res.status_code == 409
    assert "Project name duplicate" in dup_res.json()["detail"]

    # 5. Project Selection POST /api/projects/select
    sel_res = client.post("/api/projects/select", json={"project_id": created_id})
    assert sel_res.status_code == 200
    assert sel_res.json()["redirect_url"] == "/workspace"
    assert sel_res.json()["active_project_id"] == created_id

    # 6. Verify Workspace renders with active project
    res_ws_active = client.get("/workspace")
    assert res_ws_active.status_code == 200
    assert test_name in res_ws_active.text
    assert created_id in res_ws_active.text

    # Clean up project
    del_res = client.delete(f"/api/projects/{created_id}")
    assert del_res.status_code == 200

    # Ensure duplicate is STILL rejected when soft-deleted
    dup_deleted_res = client.post("/api/projects/create", json={"name": test_name})
    assert dup_deleted_res.status_code == 409


if __name__ == "__main__":
    import pytest
    pytest.main(["-v", __file__])
