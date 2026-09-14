# Cerberus

An MCP access-control server that enforces least-privilege tool access
and audit logging for AI coding agents — and is specifically designed
to hold that boundary even when the agent itself is manipulated.

## Discovery brief

**Customer:** A 60-engineer B2B SaaS company piloting AI coding agents
(Claude Code, Cursor) across engineering, paused on wider rollout after
a security review.

**Pain point:** Two unresolved risks: (1) an agent could write to a
sensitive file with no review step, and (2) a hidden instruction planted
in a file the agent reads could manipulate it into acting against the
user's intent, with nothing catching or logging it.

**Constraint:** Reads must stay fast; the fix must work at the protocol
level (MCP) so it's portable across agent hosts, not bolted onto one
vendor's tool.

**Success metric:** Zero unauthorized writes and zero successful
injection-driven actions across a red-team test suite, with 100% of
tool calls reconstructable from the audit log.

## Why MCP-based access control, not just RBAC

Traditional access control (RBAC, file permissions, git branch
protection) checks *whether an identity has rights to a resource*, and
assumes the requester is honest about its intent. That assumption
breaks for AI agents in two specific ways traditional ACLs were never
built to handle:

1. **Indirect prompt injection.** A file the agent reads can contain a
   hidden instruction that manipulates what the agent *wants* to do.
   RBAC has no concept of the requester itself being compromised
   mid-task.
2. **Decomposition / the aggregation problem.** Several individually
   permitted actions can combine into something that should have been
   forbidden as a whole (analogous to reconstructing redacted
   information by combining separately-compliant disclosures).

Cerberus's core design principle — the server enforces every call
independently, never trusting the agent's stated reasoning — is a
direct response to (1). (2) is named as a known limitation below,
not solved.

## Architecture

Claude Desktop (host) → MCP client → Cerberus (server) → sandbox
target repo, with every call logged to an audit trail before it
reaches the filesystem. `search_codebase` is read-only and
role-scoped; `propose_edit` (planned) never writes directly — it
queues for human approval.


## Known limitations

- **Decomposition attacks are not yet defended against.** The current
  design checks each tool call independently and has no session-level
  memory of what's been assembled across multiple allowed reads. This
  is a real, unsolved gap — named intentionally rather than hidden.
- The `role` used for scoping is set at server-config time, not tied to
  a real authenticated identity — a production version would need this
  sourced from an actual auth layer.

## Credits

Planted injection phrasing in the sandbox fixture is inspired by
patterns documented in `deepset/prompt-injections` (Apache-2.0).

## License

MIT