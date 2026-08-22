"""
ViperACL — Centralized Audit Logging Module

Provides persistent, append-only JSONL logging for forensic evidence,
plus an async SSE fan-out system for real-time log streaming to the web UI.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Log severity levels (ordered by severity)
# ---------------------------------------------------------------------------
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LEVEL_SET = set(LEVELS)

# ---------------------------------------------------------------------------
# Action categories for filtering
# ---------------------------------------------------------------------------
CATEGORIES = (
    "SYSTEM",
    "INGEST",
    "PROJECT",
    "PATHFINDER",
    "PRIVESC",
    "REMEDIATION",
    "DATABASE",
    "CONFIG",
    "AUTH",
    "API",
)
CATEGORY_SET = set(CATEGORIES)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOG_DIR = _PROJECT_ROOT / "data" / "logs"
_LOG_FILE = _LOG_DIR / "viperacl_audit.jsonl"


# ---------------------------------------------------------------------------
# Structured log entry
# ---------------------------------------------------------------------------
@dataclass
class ViperLog:
    """A single structured audit log entry."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = ""
    date: str = ""
    time: str = ""
    level: str = "INFO"
    category: str = "SYSTEM"
    action: str = ""
    message: str = ""
    project_id: str | None = None
    user: str = "system"
    details: dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).astimezone()
        if not self.timestamp:
            self.timestamp = now.isoformat()
        if not self.date:
            self.date = now.strftime("%b %d, %Y")
        if not self.time:
            self.time = now.strftime("%I:%M:%S %p")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# Singleton logger
# ---------------------------------------------------------------------------
class ViperLogger:
    """
    Thread-safe, singleton audit logger.

    * Writes append-only JSONL to ``data/logs/viperacl_audit.jsonl``.
    * Maintains a set of ``asyncio.Queue`` subscribers for SSE fan-out.
    """

    _instance: ViperLogger | None = None
    _lock = threading.Lock()

    def __new__(cls) -> ViperLogger:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._init_once()
                    cls._instance = inst
        return cls._instance

    # -- internal init (called exactly once) --------------------------------
    def _init_once(self):
        self._file_lock = threading.Lock()
        self._subscribers: list[asyncio.Queue] = []
        self._sub_lock = threading.Lock()
        _LOG_DIR.mkdir(parents=True, exist_ok=True)

    # -- core emit ----------------------------------------------------------
    def emit(
        self,
        level: str = "INFO",
        category: str = "SYSTEM",
        action: str = "",
        message: str = "",
        project_id: str | None = None,
        user: str = "system",
        details: dict[str, Any] | None = None,
        source: str = "",
    ) -> ViperLog:
        """Create, persist, and broadcast a log entry."""
        entry = ViperLog(
            level=level.upper(),
            category=category.upper(),
            action=action,
            message=message,
            project_id=project_id,
            user=user,
            details=details or {},
            source=source,
        )

        # 1. Persist to disk (append-only, thread-safe)
        line = entry.to_json() + "\n"
        with self._file_lock:
            with open(_LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line)

        # 2. Fan-out to SSE subscribers
        self._broadcast(entry)

        return entry

    # -- convenience shortcuts ----------------------------------------------
    def debug(self, category, action, message, **kw) -> ViperLog:
        return self.emit("DEBUG", category, action, message, **kw)

    def info(self, category, action, message, **kw) -> ViperLog:
        return self.emit("INFO", category, action, message, **kw)

    def warning(self, category, action, message, **kw) -> ViperLog:
        return self.emit("WARNING", category, action, message, **kw)

    def error(self, category, action, message, **kw) -> ViperLog:
        return self.emit("ERROR", category, action, message, **kw)

    def critical(self, category, action, message, **kw) -> ViperLog:
        return self.emit("CRITICAL", category, action, message, **kw)

    # -- SSE subscriber management ------------------------------------------
    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE client queue and return it."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._sub_lock:
            self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """Remove an SSE client queue."""
        with self._sub_lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass

    def _broadcast(self, entry: ViperLog):
        """Push a log entry to every active subscriber queue."""
        data = entry.to_dict()
        with self._sub_lock:
            dead: list[asyncio.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(data)
                except asyncio.QueueFull:
                    # Client is too slow — drop the oldest entry and retry
                    try:
                        q.get_nowait()
                        q.put_nowait(data)
                    except Exception:
                        dead.append(q)
                except Exception:
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    # -- query / filter -----------------------------------------------------
    def get_logs(
        self,
        limit: int = 200,
        offset: int = 0,
        level: str | None = None,
        category: str | None = None,
        project_id: str | None = None,
        search: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Read logs from the JSONL file, apply filters, and return a
        (page, total_matching) tuple.

        Reads the file in reverse so newest entries come first.
        """
        if not _LOG_FILE.exists():
            return [], 0

        # Read all lines (reverse chronological)
        with open(_LOG_FILE, "r", encoding="utf-8") as fh:
            raw_lines = fh.readlines()

        raw_lines.reverse()

        filtered: list[dict[str, Any]] = []
        level_upper = level.upper() if level else None
        category_upper = category.upper() if category else None
        search_lower = search.lower() if search else None

        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Apply filters
            if level_upper and entry.get("level", "").upper() != level_upper:
                continue
            if category_upper and entry.get("category", "").upper() != category_upper:
                continue
            if project_id:
                if project_id in ("__NONE__", "NONE", "null"):
                    if entry.get("project_id"):
                        continue
                elif entry.get("project_id") != project_id:
                    continue
            if search_lower:
                searchable = (
                    entry.get("message", "")
                    + " "
                    + entry.get("action", "")
                    + " "
                    + entry.get("source", "")
                    + " "
                    + json.dumps(entry.get("details", {}))
                ).lower()
                if search_lower not in searchable:
                    continue
            if date_from:
                entry_ts = entry.get("timestamp", "")
                if entry_ts < date_from:
                    continue
            if date_to:
                entry_ts = entry.get("timestamp", "")
                if entry_ts > date_to:
                    continue

            filtered.append(entry)

        total = len(filtered)
        page = filtered[offset : offset + limit]
        return page, total

    def get_stats(self) -> dict[str, Any]:
        """Return aggregated counts by level and category."""
        level_counts = {lv: 0 for lv in LEVELS}
        category_counts = {cat: 0 for cat in CATEGORIES}
        total = 0

        if not _LOG_FILE.exists():
            return {
                "total": total,
                "by_level": level_counts,
                "by_category": category_counts,
            }

        with open(_LOG_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                lv = entry.get("level", "INFO").upper()
                if lv in level_counts:
                    level_counts[lv] += 1
                cat = entry.get("category", "SYSTEM").upper()
                if cat in category_counts:
                    category_counts[cat] += 1

        return {
            "total": total,
            "by_level": level_counts,
            "by_category": category_counts,
        }


# ---------------------------------------------------------------------------
# Module-level convenience: importable singleton
# ---------------------------------------------------------------------------
logger = ViperLogger()
