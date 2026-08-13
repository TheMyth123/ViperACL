from dataclasses import dataclass
from pathlib import Path
import os

import yaml


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


def load_settings():
    project_root = Path(__file__).resolve().parents[1]
    config_path = project_root / "config.yaml"
    config = {}

    if not config_path.exists():
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
            }
        }
        try:
            with config_path.open("w", encoding="utf-8") as handle:
                yaml.dump(default_config, handle, default_flow_style=False)
        except Exception:
            pass

    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception:
            config = {}

    web_cfg = config.get("web", {})
    neo4j_cfg = config.get("neo4j", {})

    return AppSettings(
        title=os.getenv("VIPERACL_TITLE") or web_cfg.get("title") or "ViperACL",
        version=os.getenv("VIPERACL_VERSION") or "0.1.0",
        host=os.getenv("VIPERACL_WEB_HOST") or web_cfg.get("host") or "127.0.0.1",
        port=int(os.getenv("VIPERACL_WEB_PORT") or web_cfg.get("port") or 8000),
        neo4j_uri=os.getenv("VIPERACL_NEO4J_URI") or neo4j_cfg.get("uri") or "bolt://127.0.0.1:7687",
        neo4j_username=os.getenv("VIPERACL_NEO4J_USERNAME") or neo4j_cfg.get("username") or "neo4j",
        neo4j_password=os.getenv("VIPERACL_NEO4J_PASSWORD") or neo4j_cfg.get("password") or "viperacl",
        neo4j_database=os.getenv("VIPERACL_NEO4J_DATABASE") or neo4j_cfg.get("database") or "neo4j",
    )