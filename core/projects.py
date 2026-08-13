import os
import json
import time
from datetime import datetime

class ProjectManager:
    def __init__(self, projects_dir=None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.projects_dir = projects_dir or os.path.join(base_dir, "data", "projects")
        self.registry_file = os.path.join(self.projects_dir, "projects.json")
        self._ensure_storage()

    def _ensure_storage(self):
        """Ensures the projects directory and projects.json file exist."""
        os.makedirs(self.projects_dir, exist_ok=True)
        if not os.path.exists(self.registry_file):
            default_data = {
                "active_project_id": None,
                "projects": {}
            }
            self._save_data(default_data)

    def _load_data(self):
        """Loads data from projects.json safely."""
        try:
            with open(self.registry_file, "r") as f:
                return json.load(f)
        except Exception:
            return {"active_project_id": None, "projects": {}}

    def _save_data(self, data):
        """Saves data to projects.json atomically."""
        temp_file = f"{self.registry_file}.tmp"
        with open(temp_file, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(temp_file, self.registry_file)

    def list_projects(self, include_deleted=False):
        """
        Returns a list of project metadata dictionaries.
        Hides soft-deleted projects by default to keep sidebar clean.
        """
        data = self._load_data()
        projects_dict = data.get("projects", {})
        active_id = data.get("active_project_id")

        result = []
        for p_id, p_info in projects_dict.items():
            if not include_deleted and p_info.get("is_deleted"):
                continue
            info_copy = dict(p_info)
            info_copy["is_active"] = (p_id == active_id)
            result.append(info_copy)

        # Sort by creation time descending
        result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return result

    def get_project(self, project_id):
        """Returns metadata for a specific project."""
        data = self._load_data()
        return data.get("projects", {}).get(project_id)

    def get_active_project_id(self):
        """Returns the currently active project_id (or None if no active project)."""
        data = self._load_data()
        active_id = data.get("active_project_id")
        projects = data.get("projects", {})
        if active_id in projects and not projects[active_id].get("is_deleted"):
            return active_id
        return None

    def set_active_project(self, project_id):
        """Sets the active project_id if it exists and is not deleted."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            data["active_project_id"] = project_id
            self._save_data(data)
            return True
        return False

    def register_project(self, project_id, name, source_zip, nodes=0, relationships=0):
        """Registers or updates a project in the registry."""
        data = self._load_data()
        projects = data.get("projects", {})

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        project_entry = {
            "project_id": project_id,
            "name": name,
            "source_zip": source_zip,
            "nodes": nodes,
            "relationships": relationships,
            "created_at": now_str,
            "status": "Ready",
            "is_deleted": False,
        }

        projects[project_id] = project_entry
        data["projects"] = projects
        data["active_project_id"] = project_id
        self._save_data(data)
        return project_entry

    def update_project_stats(self, project_id, nodes, relationships):
        """Updates node and relationship counts for a project."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["nodes"] = nodes
            projects[project_id]["relationships"] = relationships
            self._save_data(data)
            return True
        return False

    def delete_project(self, project_id):
        """
        Soft-deletes a project in the registry.
        Preserves metadata for evidence and audit purposes, while hiding from active project list.
        """
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            projects[project_id]["status"] = "Deleted"
            projects[project_id]["is_deleted"] = True
            projects[project_id]["deleted_at"] = now_str
            projects[project_id]["nodes"] = 0
            projects[project_id]["relationships"] = 0

            if data.get("active_project_id") == project_id:
                active_candidates = [
                    pid for pid, pinfo in projects.items()
                    if not pinfo.get("is_deleted")
                ]
                data["active_project_id"] = active_candidates[0] if active_candidates else None

            self._save_data(data)
            return True
        return False
