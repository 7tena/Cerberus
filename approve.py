"""Human review of queued edit proposals. Run by a person, in a terminal.
Never expose this to the agent.

  uv run approve.py --repo /path/to/sandbox_repo list
  uv run approve.py --repo /path/to/sandbox_repo show 1
  uv run approve.py --repo /path/to/sandbox_repo approve 1
  uv run approve.py --repo /path/to/sandbox_repo reject 1
"""
import argparse
import difflib
import hashlib
import os
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from core import DB_PATH, init_db, is_restricted, log_event, resolve_target

REVIEWER = "human"


def safe(text: str) -> str:
    """Agent-controlled text must not be able to drive the terminal."""
    return "".join(
        c if c in "\n\t" or c.isprintable() else f"\\x{ord(c):02x}" for c in text
    )


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_proposal(conn, proposal_id: int):
    return conn.execute(
        "SELECT * FROM pending_edits WHERE id = ?", (proposal_id,)
    ).fetchone()


def set_status(conn, proposal_id: int, status: str) -> int:
    cur = conn.execute(
        "UPDATE pending_edits SET status = ?, decided_at = ? "
        "WHERE id = ? AND status = 'pending'",
        (status, datetime.now(timezone.utc).isoformat(), proposal_id),
    )
    conn.commit()
    return cur.rowcount


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def render_diff(path: str, old: str, new: str) -> str:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return safe("".join(diff)) or "(no textual changes)"


def write_atomic(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        if target.exists():
            os.chmod(tmp, target.stat().st_mode)
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def cmd_list(repo: Path) -> None:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT id, ts, role, path, status FROM pending_edits ORDER BY id"
        ).fetchall()
    if not rows:
        print("No proposals.")
        return
    for r in rows:
        print(f"#{r['id']}  {r['status']:<9} role={r['role']:<8} {safe(r['path'])}  ({r['ts']})")


def cmd_show(repo: Path, proposal_id: int) -> None:
    with closing(connect()) as conn:
        row = get_proposal(conn, proposal_id)
    if row is None:
        sys.exit("No such proposal.")
    resolved = resolve_target(repo, row["path"])
    if resolved is None:
        sys.exit("Proposal path is outside the repo.")
    absolute, relative = resolved
    old = absolute.read_text(errors="replace") if absolute.exists() else ""
    print(f"Proposal #{row['id']} | status={row['status']} | proposed by role={row['role']}")
    print(f"File: {relative}\n")
    print(render_diff(str(relative), old, row["new_content"]))


def cmd_approve(repo: Path, proposal_id: int) -> None:
    with closing(connect()) as conn:
        row = get_proposal(conn, proposal_id)
        if row is None:
            sys.exit("No such proposal.")
        if row["status"] != "pending":
            sys.exit(f"Proposal #{proposal_id} is already {row['status']}.")

        # 1. Re-check policy. Never trust the queue.
        resolved = resolve_target(repo, row["path"])
        if (
            resolved is None
            or is_restricted(resolved[1], row["role"])
            or (resolved[0].exists() and not resolved[0].is_file())
        ):
            set_status(conn, proposal_id, "blocked")
            log_event("approve.py", REVIEWER, {"proposal_id": proposal_id},
                      "blocked", "failed policy re-check at approval time")
            sys.exit("Blocked: this proposal no longer passes the access policy.")
        absolute, relative = resolved

        # 2. Has the file changed since the proposal was made?
        if file_hash(absolute) != row["base_hash"]:
            set_status(conn, proposal_id, "stale")
            log_event("approve.py", REVIEWER,
                      {"proposal_id": proposal_id, "path": str(relative)},
                      "stale", "file changed after proposal")
            sys.exit("Stale: the file changed since this was proposed. Ask for a new proposal.")

        old = absolute.read_text(errors="replace") if absolute.exists() else ""
        print(f"Proposal #{row['id']} | proposed by role={row['role']} | file: {relative}\n")
        print(render_diff(str(relative), old, row["new_content"]))
        print()

        answer = input(f"Apply proposal #{proposal_id}? Type 'yes' to confirm: ")
        if answer.strip().lower() != "yes":
            print("Not applied. Proposal remains pending.")
            return

        # 3. Re-check the hash after the human has taken their time.
        if file_hash(absolute) != row["base_hash"]:
            set_status(conn, proposal_id, "stale")
            log_event("approve.py", REVIEWER,
                      {"proposal_id": proposal_id, "path": str(relative)},
                      "stale", "file changed during review")
            sys.exit("Stale: the file changed while you were reviewing. Nothing applied.")

        write_atomic(absolute, row["new_content"])
        if set_status(conn, proposal_id, "approved") == 0:
            print("Warning: proposal status was changed by someone else.")
        log_event("approve.py", REVIEWER,
                  {"proposal_id": proposal_id, "path": str(relative)},
                  "approved", f"proposer_role={row['role']}")
        print(f"Applied proposal #{proposal_id} to {relative}.")


def cmd_reject(repo: Path, proposal_id: int) -> None:
    with closing(connect()) as conn:
        row = get_proposal(conn, proposal_id)
        if row is None:
            sys.exit("No such proposal.")
        if set_status(conn, proposal_id, "rejected") == 0:
            sys.exit(f"Proposal #{proposal_id} is already {row['status']}.")
        log_event("approve.py", REVIEWER,
                  {"proposal_id": proposal_id, "path": row["path"]},
                  "rejected", f"proposer_role={row['role']}")
        print(f"Rejected proposal #{proposal_id}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Review Cerberus edit proposals.")
    parser.add_argument("--repo", required=True, help="Path to the target repo (sandbox_repo)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    for name in ("show", "approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("id", type=int)
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        sys.exit(f"Repo path is not a directory: {repo}")

    init_db()
    if args.command == "list":
        cmd_list(repo)
    elif args.command == "show":
        cmd_show(repo, args.id)
    elif args.command == "approve":
        cmd_approve(repo, args.id)
    elif args.command == "reject":
        cmd_reject(repo, args.id)


if __name__ == "__main__":
    main()