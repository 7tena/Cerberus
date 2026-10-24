import os
from pathlib import Path
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("Cerberus")

REPO_PATH = Path(os.environ["REPO_PATH"]).resolve()

# Fail closed: only an exact "engineer" gets elevated access
ROLE = "engineer" if os.environ.get("ROLE", "").strip().lower() == "engineer" else "guest"

# Never visible, regardless of role
FORBIDDEN_DIRS = {"secrets"}
# Hidden from guests only
GUEST_RESTRICTED_DIRS = {"config"}


@mcp.tool()
def search_codebase(query: str) -> str:
    """Search the codebase for files containing the given text.
    Read-only. Some paths are restricted based on the server's configured role."""
    matches = []

    for path in REPO_PATH.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(REPO_PATH)
        top_level = relative.parts[0] if relative.parts else ""

        if top_level in FORBIDDEN_DIRS:
            continue
        if ROLE == "guest" and top_level in GUEST_RESTRICTED_DIRS:
            continue

        try:
            text = path.read_text(errors="ignore")
        except (UnicodeDecodeError, PermissionError):
            continue

        if query.lower() in text.lower():
            matches.append(str(relative))

    if not matches:
        return f"No matches found for '{query}'."
    return "Matches found in:\n" + "\n".join(matches)


if __name__ == "__main__":
    mcp.run()