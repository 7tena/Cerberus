import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("Cerberus")

REPO_PATH = Path(os.environ["REPO_PATH"]).resolve()

# Fail closed: only an exact "engineer" gets elevated access
ROLE = "engineer" if os.environ.get("ROLE", "").strip().lower() == "engineer" else "guest"

FORBIDDEN_DIRS = {"secrets"}
GUEST_RESTRICTED_DIRS = {"config"}

# Outside the sandbox repo and outside the extension folder
DB_PATH = Path.home() / ".cerberus" / "audit.db"


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
        conn.commit()


def log_event(tool: str, arguments: dict, outcome: str, detail: str = "") -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, tool, role, arguments, outcome, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                tool,
                ROLE,
                json.dumps(arguments),
                outcome,
                detail,
            ),
        )
        conn.commit()


init_db()


@mcp.tool()
def search_codebase(query: str) -> str:
    """Search the codebase for files containing the given text. Read-only."""
    matches = []
    withheld = 0

    for path in REPO_PATH.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(REPO_PATH)
        top_level = relative.parts[0] if relative.parts else ""

        restricted = top_level in FORBIDDEN_DIRS or (
            ROLE == "guest" and top_level in GUEST_RESTRICTED_DIRS
        )

        try:
            text = path.read_text(errors="ignore")
        except (UnicodeDecodeError, PermissionError):
            continue

        if query.lower() in text.lower():
            if restricted:
                withheld += 1  # counted for the audit log, never shown to the agent
            else:
                matches.append(str(relative))

    outcome = "partial" if withheld else "allowed"
    log_event(
        "search_codebase",
        {"query": query},
        outcome,
        f"matches_returned={len(matches)}, matches_withheld={withheld}",
    )

    if not matches:
        return f"No matches found for '{query}'."
    return "Matches found in:\n" + "\n".join(matches)


if __name__ == "__main__":
    mcp.run()