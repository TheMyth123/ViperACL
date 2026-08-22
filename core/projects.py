import json
import re
from datetime import datetime
from pathlib import Path


# Strict regex pattern for safe project names: alphanumeric, spaces, hyphens, underscores, dots, parentheses, brackets
PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\. ()\[\]]{3,64}$")
# Regex pattern for safe usernames (without domain prefix): alphanumeric, underscores, hyphens, dots
SAFE_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
# Regex pattern for safe domain names / hostnames
SAFE_DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")
# Regex pattern for safe IP addresses / hostnames
SAFE_IP_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")


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


def validate_dc_ip(dc_ip: str | None) -> tuple[bool, str]:
    """
    Validates a Domain Controller IP or hostname.
    Returns (is_valid, cleaned_ip_or_error_message).
    """
    if not dc_ip:
        return True, ""
    if not isinstance(dc_ip, str):
        return False, "Domain Controller IP must be a string."

    cleaned = dc_ip.strip()
    if not cleaned:
        return True, ""
    if len(cleaned) > 128:
        return False, "Domain Controller IP / host cannot exceed 128 characters."
    if any(c in cleaned for c in ["\0", "<", ">", '"', "'", "\\", "/", "`", ";", " "]):
        return False, "Domain Controller IP contains disallowed characters."
    if not SAFE_IP_REGEX.match(cleaned):
        return False, "Domain Controller IP must be a valid IP address or hostname."
    return True, cleaned


def validate_foothold_username(username: str | None) -> tuple[bool, str]:
    """
    Validates a foothold username (without domain prefix).
    Automatically strips domain prefixes (DOMAIN\\ or @DOMAIN) if provided.
    Returns (is_valid, cleaned_username_or_error_message).
    """
    if not username:
        return True, ""
    if not isinstance(username, str):
        return False, "Foothold username must be a string."

    cleaned = username.strip()
    if not cleaned:
        return True, ""

    # Strip domain prefix if user typed DOMAIN\user or user@domain.local
    if "\\" in cleaned:
        cleaned = cleaned.split("\\")[-1].strip()
    if "@" in cleaned:
        cleaned = cleaned.split("@")[0].strip()

    if len(cleaned) > 64:
        return False, "Foothold username cannot exceed 64 characters."
    if any(c in cleaned for c in ["\0", "<", ">", '"', "'", "\\", "/", "`", ";", " "]):
        return False, "Foothold username contains disallowed characters."
    if not SAFE_USERNAME_REGEX.match(cleaned):
        return False, "Foothold username must contain only letters, numbers, dots, dashes, or underscores."
    return True, cleaned


def validate_foothold_password(password: str | None) -> tuple[bool, str]:
    """
    Validates a foothold password against injection and null-byte sequences.
    Returns (is_valid, password_or_error_message).
    """
    if not password:
        return True, ""
    if not isinstance(password, str):
        return False, "Foothold password must be a string."
    if len(password) > 256:
        return False, "Foothold password cannot exceed 256 characters."
    if "\0" in password:
        return False, "Foothold password contains disallowed null byte characters."
    return True, password


def validate_domain(domain: str | None) -> tuple[bool, str]:
    """
    Validates an Active Directory domain name.
    Returns (is_valid, cleaned_domain_or_error_message).
    """
    if not domain:
        return True, ""
    if not isinstance(domain, str):
        return False, "Domain name must be a string."
    cleaned = domain.strip().upper()
    if not cleaned:
        return True, ""
    if len(cleaned) > 128:
        return False, "Domain name cannot exceed 128 characters."
    if any(c in cleaned for c in ["\0", "<", ">", '"', "'", "\\", "/", "`", ";", " "]):
        return False, "Domain name contains disallowed characters."
    if not SAFE_DOMAIN_REGEX.match(cleaned):
        return False, "Domain name must contain only letters, numbers, dots, dashes, or underscores."
    return True, cleaned


def generate_safe_project_id(name: str) -> str:
    """Generates a sanitized, timestamp-prefixed project_id for chronological sorting."""
    cleaned = " ".join(name.strip().split())
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", cleaned.lower()).strip("_")
    if not slug:
        slug = "project"
    timestamp_slug = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{timestamp_slug}_{slug[:32]}"


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

    def get_project_dir(self, project_id: str) -> Path:
        """
        Returns the dedicated storage directory for a project's files (staging archives, scripts).
        Files are organized under data/projects/storage/{project_id}/.
        """
        if not project_id:
            storage_dir = self.projects_dir / "storage" / "default"
            storage_dir.mkdir(parents=True, exist_ok=True)
            return storage_dir
        storage_dir = self.projects_dir / "storage" / project_id
        if not storage_dir.exists():
            # Check legacy location directly under data/projects/{project_id}
            legacy_dir = self.projects_dir / project_id
            if legacy_dir.exists() and legacy_dir.is_dir():
                return legacy_dir
        storage_dir.mkdir(parents=True, exist_ok=True)
        return storage_dir

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
        info.setdefault("dc_ip", "")
        info.setdefault("foothold_username", "")
        info.setdefault("foothold_password", "")
        info.setdefault("domain", "")
        info.setdefault("privesc_success_records", [])
        info.setdefault("remediation_scripts", [])
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

    def register_project(
        self,
        project_id: str,
        name: str,
        dc_ip: str = "",
        foothold_username: str = "",
        foothold_password: str = "",
        domain: str = "",
        source_zip: str | None = None,
        nodes: int = 0,
        relationships: int = 0,
        unlocked_phase: str = "phase_1",
    ) -> dict:
        """Registers or updates a project in the registry."""
        data = self._load_data()
        projects = data.get("projects", {})

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        project_entry = {
            "project_id": project_id,
            "name": name,
            "dc_ip": dc_ip or "",
            "foothold_username": foothold_username or "",
            "foothold_password": foothold_password or "",
            "domain": domain or "",
            "source_zip": source_zip,
            "nodes": nodes,
            "relationships": relationships,
            "unlocked_phase": unlocked_phase,
            "created_at": now_str,
            "status": "Ready",
            "is_deleted": False,
            "privesc_success_records": [],
        }

        projects[project_id] = project_entry
        data["projects"] = projects
        data["active_project_id"] = project_id
        self._save_data(data)
        return self._normalize_project_entry(project_entry)

    def update_project_target(
        self,
        project_id: str,
        dc_ip: str | None = None,
        foothold_username: str | None = None,
        foothold_password: str | None = None,
        domain: str | None = None,
    ) -> dict | None:
        """Updates target and foothold credentials for a project."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            if dc_ip is not None:
                projects[project_id]["dc_ip"] = dc_ip
            if foothold_username is not None:
                projects[project_id]["foothold_username"] = foothold_username
            if foothold_password is not None:
                projects[project_id]["foothold_password"] = foothold_password
            if domain not in (None, ""):
                projects[project_id]["domain"] = domain
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

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

    def reset_project_pipeline_on_reingest(self, project_id: str, nodes: int, relationships: int, source_zip: str | None = None) -> dict | None:
        """
        Resets Phase 3 and Phase 4 locks, clears selected paths, privesc records,
        and remediation script history when a new archive is ingested.
        """
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            projects[project_id]["nodes"] = nodes
            projects[project_id]["relationships"] = relationships
            if source_zip is not None:
                projects[project_id]["source_zip"] = source_zip

            # Lock Phase 3 & Phase 4: Reset unlocked_phase to phase_2 if nodes > 0, else phase_1
            projects[project_id]["unlocked_phase"] = "phase_2" if nodes > 0 else "phase_1"
            projects[project_id]["last_active_phase"] = "phase_2" if nodes > 0 else "phase_1"

            # Clear pathfinder selection history
            projects[project_id]["selected_engine"] = None
            projects[project_id]["selected_path"] = None
            projects[project_id]["selected_candidate_paths"] = None
            projects[project_id]["selected_path_index"] = 0
            projects[project_id]["selected_source"] = None
            projects[project_id]["selected_target"] = None

            # Clear PrivEsc execution history
            projects[project_id]["privesc_success_records"] = []

            # Clear Remediation script history
            projects[project_id]["remediation_scripts"] = []

            self._save_data(data)

            # Also remove physical script files from project scripts directory on disk
            try:
                scripts_dir = self.get_project_dir(project_id) / "scripts"
                if scripts_dir.exists():
                    for s_file in scripts_dir.glob("*.ps1"):
                        try:
                            s_file.unlink()
                        except OSError:
                            pass
            except Exception:
                pass

            return self._normalize_project_entry(projects[project_id])
        return None

    def append_privesc_success_record(self, project_id: str, record: dict) -> dict | None:
        """Appends a completed privesc result record to the project registry."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            records = list(projects[project_id].get("privesc_success_records", []))
            records.insert(0, record)
            projects[project_id]["privesc_success_records"] = records[:25]
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

    def add_remediation_script(self, project_id: str, script_record: dict) -> dict | None:
        """Appends a remediation script record to a project and saves atomically."""
        data = self._load_data()
        projects = data.get("projects", {})
        if project_id in projects and not projects[project_id].get("is_deleted"):
            scripts = projects[project_id].setdefault("remediation_scripts", [])
            # Insert newest script at index 0
            scripts.insert(0, script_record)
            self._save_data(data)
            return self._normalize_project_entry(projects[project_id])
        return None

    def get_remediation_scripts(self, project_id: str) -> list[dict]:
        """Returns the list of remediation scripts generated for a project."""
        proj = self.get_project(project_id)
        if proj:
            return proj.get("remediation_scripts", [])
        return []

    def get_remediation_script_by_id(self, project_id: str, script_id: str) -> dict | None:
        """Finds a specific remediation script record by script_id."""
        scripts = self.get_remediation_scripts(project_id)
        for s in scripts:
            if s.get("id") == script_id or s.get("filename") == script_id:
                return s
        return None

