"""Shared policy and storage for Cerberus (used by server.py and approve.py)."""
import difflib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

# Outside the sandbox repo and outside the extension folder
DB_PATH = Path.home() / ".cerberus" / "audit.db"

# Never accessible, regardless of role
FORBIDDEN_DIRS = {"secrets"}
# Hidden from guests only
GUEST_RESTRICTED_DIRS = {"config"}


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                tool TEXT NOT NULL,
                role TEXT NOT NULL,
                arguments TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS pending_edits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                role TEXT NOT NULL,
                path TEXT NOT NULL,
                new_content TEXT NOT NULL,
                base_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                decided_at TEXT
            )"""
        )
        conn.commit()


def log_event(tool: str, role: str, arguments: dict, outcome: str, detail: str = "") -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, tool, role, arguments, outcome, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                tool,
                role,
                json.dumps(arguments),
                outcome,
                detail,
            ),
        )
        conn.commit()


def resolve_target(repo_path: Path, rel: str):
    """Resolve an agent-supplied path. Returns (absolute, relative),
    or None if it escapes the repo or is malformed."""
    try:
        candidate = (repo_path / rel).resolve()
    except (ValueError, OSError):
        return None
    if not candidate.is_relative_to(repo_path):
        return None
    return candidate, candidate.relative_to(repo_path)


def is_restricted(relative: Path, role: str) -> bool:
    top_level = relative.parts[0].lower() if relative.parts else ""
    return top_level in FORBIDDEN_DIRS or (
        role == "guest" and top_level in GUEST_RESTRICTED_DIRS
    )

def safe(text: str) -> str:
    """Agent-controlled text must not be able to drive the terminal."""
    return "".join(
        c if c in "\n\t" or c.isprintable() else f"\\x{ord(c):02x}" for c in text
    )


def render_diff(path: str, old: str, new: str) -> str:
    if old == new:
        return "(no changes)"
    lines = list(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="",
        )
    )
    if not lines:
        return "(only line-ending or trailing-newline differences)"
    return safe("\n".join(lines))