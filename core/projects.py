import json
import re
from datetime import datetime
from pathlib import Path


# Strict regex pattern for safe project names: alphanumeric, spaces, hyphens, underscores, dots, parentheses, brackets
PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\. ()\[\]]{3,64}$")


def validate_project_name(name: str) -> tuple[bool, str]:
    """
    Validates a project name against security requirements:
    - Strips whitespace and normalizes spaces
    - Length between 3 and 64 characters
    - Only safe characters allowed (no path traversal, script tags, quotes, control chars)
    Returns (is_valid, cleaned_name_or_error_message).
    """
    if not name or not isinstance(name, str):
        return False, "Project name is required and cannot be empty."

    cleaned = " ".join(name.strip().split())
    if len(cleaned) < 3:
        return False, "Project name must be at least 3 characters long."
    if len(cleaned) > 64:
        return False, "Project name cannot exceed 64 characters."

    # Prevent path traversal, null bytes, HTML/script tags, control characters
    if any(c in cleaned for c in ["\0", "<", ">", '"', "'", "\\", "/", "`", ";"]):
        return False, "Project name contains disallowed or potentially malicious characters."

    if not PROJECT_NAME_REGEX.match(cleaned):
        return False, "Project name contains invalid characters. Use letters, numbers, spaces, underscores, dashes, dots, or parentheses."

    return True, cleaned


def generate_safe_project_id(name: str) -> str:
    """Generates a sanitized, deterministic-prefix project_id with timestamp."""
    cleaned = " ".join(name.strip().split())
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", cleaned.lower()).strip("_")
    if not slug:
        slug = "project"
    timestamp_slug = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"proj_{slug[:32]}_{timestamp_slug}"


class ProjectManager:
    def __init__(self, projects_dir=None):
        base_dir = Path(__file__).resolve().parent.parent
        self.projects_dir = Path(projects_dir) if projects_dir else base_dir / "data" / "projects"
        self.registry_file = self.projects_dir / "projects.json"
        self._ensure_storage()

    def _ensure_storage(self):
        """Ensures the projects directory and projects.json file exist."""
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        if not self.registry_file.exists():
            self._save_data({"active_project_id": None, "projects": {}})

    def _load_data(self):
        """Loads data from projects.json safely."""
        try:
            return json.loads(self.registry_file.read_text(encoding="utf-8"))
        except Exception:
            return {"active_project_id": None, "projects": {}}

    def _save_data(self, data):
        """Saves data to projects.json atomically."""
        temp_file = self.registry_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_file.replace(self.registry_file)

    def project_name_exists(self, name: str) -> bool:
        """
        Checks if a project name already exists in projects.json (case-insensitive).
        Checks ALL projects, including soft-deleted projects, to ensure each
        project is uniquely identifiable in audit logs.
        """
        if not name:
            return False
        normalized_target = " ".join(name.strip().lower().split())
        data = self._load_data()
        projects_dict = data.get("projects", {})
        for p_info in projects_dict.values():
            existing_name = p_info.get("name", "")
            if " ".join(existing_name.strip().lower().split()) == normalized_target:
                return True
        return False

    def _normalize_project_entry(self, entry: dict) -> dict:
        """Ensures backward compatibility by populating default fields if missing."""
        if not entry:
            return entry
        info = dict(entry)
        if "unlocked_phase" not in info:
            if info.get("nodes", 0) > 0:
                info["unlocked_phase"] = "phase_2"
            else:
                info["unlocked_phase"] = "phase_1"
        info.setdefault("last_active_phase", "phase_2" if info.get("nodes", 0) > 0 else "phase_1")
        info.setdefault("selected_engine", None)
        info.setdefault("selected_source", None)
        info.setdefault("selected_target", None)
        info.setdefault("selected_path", None)
        info.setdefault("selected_candidate_paths", [])
        info.setdefault("selected_path_index", 0)
        return info

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
            info_copy = self._normalize_project_entry(p_info)
            info_copy["is_active"] = (p_id == active_id)
            result.append(info_copy)

        result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return result

    def get_project(self, project_id):
        """Returns metadata for a specific project."""
        data = self._load_data()
        entry = data.get("projects", {}).get(project_id)
        return self._normalize_project_entry(entry) if entry else None

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

    def register_project(self, project_id, name, source_zip=None, nodes=0, relationships=0, unlocked_phase="phase_1"):
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
            "unlocked_phase": unlocked_phase,
            "created_at": now_str,
            "status": "Ready",
            "is_deleted": False,
        }

        projects[project_id] = project_entry
        data["projects"] = projects
        data["active_project_id"] = project_id
        self._save_data(data)
        return project_entry

    def update_project_stats(self, project_id, nodes, relationships, source_zip=None):
        """Updates node, relationship counts, and source zip for a project."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["nodes"] = nodes
            projects[project_id]["relationships"] = relationships
            if source_zip is not None:
                projects[project_id]["source_zip"] = source_zip
            if nodes > 0 and projects[project_id].get("unlocked_phase", "phase_1") == "phase_1":
                projects[project_id]["unlocked_phase"] = "phase_2"
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

    def update_project_phase(self, project_id, phase: str):
        """Updates the unlocked phase for a project ('phase_1', 'phase_2', or 'all')."""
        if phase not in {"phase_1", "phase_2", "all"}:
            return None
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["unlocked_phase"] = phase
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

    def update_last_active_phase(self, project_id: str, phase: str):
        """Updates the last worked-on phase for a project ('phase_1', 'phase_2', 'phase_3', or 'phase_4')."""
        if phase not in {"phase_1", "phase_2", "phase_3", "phase_4"}:
            return None
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["last_active_phase"] = phase
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

    def update_project_path(self, project_id, engine, path_data, source_name=None, target_name=None, unlock_phase=None, candidate_paths=None, selected_path_index=0):
        """Updates the active path selection and candidate options for a project, and optionally advances unlocked_phase and last_active_phase."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["selected_engine"] = engine
            projects[project_id]["selected_path"] = path_data
            if candidate_paths is not None:
                projects[project_id]["selected_candidate_paths"] = candidate_paths
            if selected_path_index is not None:
                projects[project_id]["selected_path_index"] = selected_path_index
            if source_name is not None:
                projects[project_id]["selected_source"] = source_name
            if target_name is not None:
                projects[project_id]["selected_target"] = target_name
            if unlock_phase in {"phase_1", "phase_2", "all"}:
                projects[project_id]["unlocked_phase"] = unlock_phase
                projects[project_id]["last_active_phase"] = "phase_3"
            else:
                projects[project_id]["last_active_phase"] = "phase_2"
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

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
