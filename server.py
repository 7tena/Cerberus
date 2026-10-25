import hashlib
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from core import (
    DB_PATH,
    FORBIDDEN_DIRS,
    GUEST_RESTRICTED_DIRS,
    init_db,
    is_restricted,
    log_event,
    resolve_target,
)

mcp = MCPServer("Cerberus")

REPO_PATH = Path(os.environ["REPO_PATH"]).resolve()

# Fail closed: only an exact "engineer" gets elevated access
ROLE = "engineer" if os.environ.get("ROLE", "").strip().lower() == "engineer" else "guest"

init_db()

MAX_SNIPPETS_PER_FILE = 3
MAX_LINE_LEN = 200
MAX_EDIT_BYTES = 100_000
DENIED_MESSAGE = "Edit rejected: this path cannot be edited."


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
        restricted = is_restricted(relative, ROLE)

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
        ROLE,
        {"query": query},
        "partial" if withheld else "allowed",
        f"lines_returned={len(results)}, files_withheld={withheld}",
    )

    if not results:
        return f"No matches found for '{query}'."
    return "\n".join(results)


@mcp.tool()
def propose_edit(path: str, new_content: str) -> str:
    """Propose replacing the full contents of a file (path relative to the
    repo root). This does NOT modify the file. The proposal is queued and a
    human must approve it. Tell the user the proposal is pending."""
    size = len(new_content.encode("utf-8"))
    args = {"path": path, "content_bytes": size}  # raw path logged, so attempts stay visible

    if size > MAX_EDIT_BYTES:
        log_event("propose_edit", ROLE, args, "denied", "content too large")
        return "Edit rejected: content too large."

    resolved = resolve_target(REPO_PATH, path)
    if resolved is None:
        log_event("propose_edit", ROLE, args, "denied", "path escapes repo")
        return DENIED_MESSAGE
    absolute, relative = resolved

    if absolute.is_dir():
        log_event("propose_edit", ROLE, args, "denied", "path is a directory")
        return DENIED_MESSAGE

    if is_restricted(relative, ROLE):
        log_event("propose_edit", ROLE, args, "denied", f"restricted path: {relative}")
        return DENIED_MESSAGE

    base_hash = ""
    if absolute.exists():
        base_hash = hashlib.sha256(absolute.read_bytes()).hexdigest()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            "INSERT INTO pending_edits (ts, role, path, new_content, base_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                ROLE,
                str(relative),
                new_content,
                base_hash,
            ),
        )
        conn.commit()
        proposal_id = cur.lastrowid

    log_event("propose_edit", ROLE, args, "queued", f"proposal_id={proposal_id}, path={relative}")
    return (
        f"Edit proposal #{proposal_id} for {relative} is queued for human "
        "approval. No changes have been made."
    )


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
        "Write access: proposals only, each requires human approval"
    )


if __name__ == "__main__":
    mcp.run()