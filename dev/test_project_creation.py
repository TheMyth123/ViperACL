"""Tests for project creation security validation, duplicate detection, and workspace routing."""

import pytest
from fastapi.testclient import TestClient

from core.projects import ProjectManager, validate_project_name, generate_safe_project_id
from web.app import create_app


def test_validate_project_name():
    # Valid names
    valid, res = validate_project_name("VIPERTECH Internal Audit")
    assert valid is True
    assert res == "VIPERTECH Internal Audit"

    valid, res = validate_project_name("Project-123_AD (Production)")
    assert valid is True

    # Too short
    valid, res = validate_project_name("ab")
    assert valid is False
    assert "at least 3 characters" in res

    # Disallowed characters & injection vectors
    valid, res = validate_project_name("<script>alert(1)</script>")
    assert valid is False

    valid, res = validate_project_name("../../etc/passwd")
    assert valid is False

    valid, res = validate_project_name("Project; DROP TABLE projects;")
    assert valid is False

    valid, res = validate_project_name("Project\0NullByte")
    assert valid is False


def test_duplicate_name_detection_including_soft_deleted():
    app = create_app()
    client = TestClient(app)

    mgr = ProjectManager()
    all_projects = mgr.list_projects(include_deleted=True)
    if len(all_projects) == 0:
        create_res = client.post("/api/projects/create", json={"name": "Initial Baseline Project"})
        assert create_res.status_code == 200
        existing_name = "Initial Baseline Project"
    else:
        existing_name = all_projects[0]["name"]

    # Attempt to create duplicate with exact name
    res = client.post("/api/projects/create", json={"name": existing_name})
    assert res.status_code == 409
    assert "Project name duplicate" in res.json()["detail"]

    # Attempt to create duplicate with different casing and whitespace
    res_casing = client.post("/api/projects/create", json={"name": f"  {existing_name.lower()}  "})
    assert res_casing.status_code == 409
    assert "Project name duplicate" in res_casing.json()["detail"]


def test_create_unique_project_and_redirect():
    app = create_app()
    client = TestClient(app)

    import uuid
    unique_name = f"Test Project {uuid.uuid4().hex[:6]}"

    res = client.post("/api/projects/create", json={"name": unique_name})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["project"]["name"] == unique_name
    assert data["redirect_url"] == "/workspace"
    assert data["active_project_id"] == data["project"]["project_id"]

    # Verify workspace endpoint renders 200 OK
    res_ws = client.get("/workspace")
    assert res_ws.status_code == 200
    assert unique_name in res_ws.text
    assert "Tactical Operations Workspace" in res_ws.text

    # Soft delete the created project for cleanup
    del_res = client.delete(f"/api/projects/{data['project']['project_id']}")
    assert del_res.status_code == 200

    # Ensure duplicate is still rejected even after deletion!
    res_dup_after_del = client.post("/api/projects/create", json={"name": unique_name})
    assert res_dup_after_del.status_code == 409
    assert "Project name duplicate" in res_dup_after_del.json()["detail"]


def test_workspace_no_active_project_greyed_out():
    app = create_app()
    client = TestClient(app)

    # Set active project to None
    mgr = ProjectManager()
    mgr._save_data({"active_project_id": None, "projects": mgr._load_data().get("projects", {})})

    res = client.get("/workspace")
    assert res.status_code == 200
    assert "No Project Selected" in res.text
    assert "opacity-30 pointer-events-none" in res.text
    assert "Create New Project" in res.text


if __name__ == "__main__":
    pytest.main(["-v", __file__])
