from dataclasses import dataclass
from pathlib import Path
import os
import json
import re


@dataclass(frozen=True)
class AppSettings:
    title: str
    version: str
    host: str
    port: int
    neo4j_uri: str
    neo4j_username: str
    neo4j_password: str
    neo4j_database: str
    pathfinder_default_mode: str
    pathfinder_max_hops: int
    pathfinder_ml_threshold: float
    privesc_default_change_password: str


def get_data_dir() -> Path:
    data_dir = Path(__file__).resolve().parents[1] / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_settings_file() -> Path:
    return get_data_dir() / "settings.json"


def validate_privesc_default_password(password: str) -> None:
    value = str(password or "")
    if len(value) < 12 or len(value) > 64:
        raise ValueError("Policy wrong: use 12-64 characters.")
    if any(character.isspace() for character in value):
        raise ValueError("Policy wrong: spaces are not allowed.")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Policy wrong: include at least one uppercase letter.")
    if not re.search(r"[a-z]", value):
        raise ValueError("Policy wrong: include at least one lowercase letter.")
    if not re.search(r"\d", value):
        raise ValueError("Policy wrong: include at least one number.")
    if not re.search(r"[^A-Za-z0-9]", value):
        raise ValueError("Policy wrong: include at least one special character.")
    if value.lower() in {"p@ssw0rd!", "password123!", "changeme123!"}:
        raise ValueError("Policy wrong: password is too common.")


def load_settings() -> AppSettings:
    settings_file = get_settings_file()
    config = {}

    default_config = {
        "web": {
            "title": "ViperACL",
            "host": "127.0.0.1",
            "port": 8000
        },
        "neo4j": {
            "uri": "bolt://127.0.0.1:7687",
            "username": "neo4j",
            "password": "viperacl",
            "database": "neo4j"
        },
        "pathfinder": {
            "default_mode": "tactical",
            "max_hops": 15,
            "ml_threshold": 0.50
        },
        "privesc": {
            "default_change_password": "Secur3P@ssw0rd!"
        }
    }

    if settings_file.exists():
        try:
            config = json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            config = {}
    else:
        config = default_config
        try:
            settings_file.write_text(json.dumps(config, indent=2), encoding="utf-8")
        except Exception:
            pass

    web_cfg = config.get("web", {})
    neo4j_cfg = config.get("neo4j", {})
    pathfinder_cfg = config.get("pathfinder", {})
    privesc_cfg = config.get("privesc", {})

    return AppSettings(
        title=os.getenv("VIPERACL_TITLE") or web_cfg.get("title") or "ViperACL",
        version=os.getenv("VIPERACL_VERSION") or "0.1.0",
        host=os.getenv("VIPERACL_WEB_HOST") or web_cfg.get("host") or "127.0.0.1",
        port=int(os.getenv("VIPERACL_WEB_PORT") or web_cfg.get("port") or 8000),
        neo4j_uri=os.getenv("VIPERACL_NEO4J_URI") or neo4j_cfg.get("uri") or "bolt://127.0.0.1:7687",
        neo4j_username=os.getenv("VIPERACL_NEO4J_USERNAME") or neo4j_cfg.get("username") or "neo4j",
        neo4j_password=os.getenv("VIPERACL_NEO4J_PASSWORD") or neo4j_cfg.get("password") or "viperacl",
        neo4j_database=os.getenv("VIPERACL_NEO4J_DATABASE") or neo4j_cfg.get("database") or "neo4j",
        pathfinder_default_mode=pathfinder_cfg.get("default_mode", "tactical"),
        pathfinder_max_hops=int(pathfinder_cfg.get("max_hops", 15)),
        pathfinder_ml_threshold=float(pathfinder_cfg.get("ml_threshold", 0.50)),
        privesc_default_change_password=os.getenv("VIPERACL_PRIVESC_DEFAULT_CHANGE_PASSWORD") or privesc_cfg.get("default_change_password") or "Secur3P@ssw0rd!",
    )


def save_settings(updates: dict):
    settings_file = get_settings_file()
    config = {}

    if settings_file.exists():
        try:
            config = json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            config = {}

    if "web" not in config:
        config["web"] = {"title": "ViperACL", "host": "127.0.0.1", "port": 8000}
    if "neo4j" not in config:
        config["neo4j"] = {"uri": "bolt://127.0.0.1:7687", "username": "neo4j", "password": "viperacl", "database": "neo4j"}
    if "pathfinder" not in config:
        config["pathfinder"] = {"default_mode": "tactical", "max_hops": 15, "ml_threshold": 0.50}
    if "privesc" not in config:
        config["privesc"] = {"default_change_password": "Secur3P@ssw0rd!"}

    if "neo4j_uri" in updates and updates["neo4j_uri"]:
        config["neo4j"]["uri"] = updates["neo4j_uri"]
    if "neo4j_username" in updates and updates["neo4j_username"]:
        config["neo4j"]["username"] = updates["neo4j_username"]
    if "neo4j_password" in updates and updates["neo4j_password"]:
        config["neo4j"]["password"] = updates["neo4j_password"]
    if "neo4j_database" in updates and updates["neo4j_database"]:
        config["neo4j"]["database"] = updates["neo4j_database"]

    if "pathfinder_default_mode" in updates and updates["pathfinder_default_mode"]:
        config["pathfinder"]["default_mode"] = updates["pathfinder_default_mode"]
    if "pathfinder_max_hops" in updates and updates["pathfinder_max_hops"] is not None:
        config["pathfinder"]["max_hops"] = int(updates["pathfinder_max_hops"])
    if "pathfinder_ml_threshold" in updates and updates["pathfinder_ml_threshold"] is not None:
        config["pathfinder"]["ml_threshold"] = float(updates["pathfinder_ml_threshold"])
    if "privesc_default_change_password" in updates and updates["privesc_default_change_password"]:
        validate_privesc_default_password(updates["privesc_default_change_password"])
        config["privesc"]["default_change_password"] = updates["privesc_default_change_password"]

    temp_file = settings_file.with_suffix(".tmp")
    temp_file.write_text(json.dumps(config, indent=2), encoding="utf-8")
    temp_file.replace(settings_file)