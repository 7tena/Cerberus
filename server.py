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


MAX_SNIPPETS_PER_FILE = 3
MAX_LINE_LEN = 200


@mcp.tool()
def search_codebase(query: str) -> str:
    """Search the codebase for the given text. Returns matching lines
    with file path and line number. Read-only."""
    results = []
    withheld = 0
    q = query.lower()

    for path in sorted(REPO_PATH.rglob("*")):
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

        hits = [
            (n, line.strip())
            for n, line in enumerate(text.splitlines(), start=1)
            if q in line.lower()
        ]
        if not hits:
            continue

        if restricted:
            withheld += 1  # logged, never shown to the agent
            continue

        for n, line in hits[:MAX_SNIPPETS_PER_FILE]:
            results.append(f"{relative}:{n}: {line[:MAX_LINE_LEN]}")

    log_event(
        "search_codebase",
        {"query": query},
        "partial" if withheld else "allowed",
        f"lines_returned={len(results)}, files_withheld={withheld}",
    )

    if not results:
        return f"No matches found for '{query}'."
    return "\n".join(results)

@mcp.resource("cerberus://audit-log")
def audit_log_resource() -> str:
    """Recent audit log entries. Not available to guest role."""
    if ROLE != "engineer":
        return "Audit log is not available for this role."

    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT ts, tool, role, arguments, outcome, detail "
            "FROM audit_log ORDER BY id DESC LIMIT 50"
        ).fetchall()

    if not rows:
        return "No audit entries yet."

    return "\n".join(
        f"{ts} | {tool} | role={role} | {arguments} | {outcome} | {detail}"
        for ts, tool, role, arguments, outcome, detail in rows
    )


@mcp.resource("cerberus://access-policy")
def access_policy_resource() -> str:
    """Describes what the current role may see."""
    if ROLE != "engineer":
        return "Access is restricted by role. Contact an administrator for details."

    return (
        f"Current role: {ROLE}\n"
        f"Never accessible to any role: {sorted(FORBIDDEN_DIRS)}\n"
        f"Hidden from guest role only: {sorted(GUEST_RESTRICTED_DIRS)}\n"
        "Write access: none (propose_edit is not yet implemented)"
    )

if __name__ == "__main__":
    mcp.run()