# Workspace manager

Status: M1 implementation note for XSY-0005. The full operator guide lands in XSY-0008.

The `x0x-symphony-workspace` crate owns the local filesystem safety boundary for runner execution.

## Invariants

- Workspaces live under the configured `workspace.root`.
- One issue maps to one deterministic path: `<workspace.root>/<sanitized-issue-id>/`.
- Sanitized issue IDs allow only `[A-Za-z0-9._-]`; other characters become `_`.
- Issue identifiers that start with `/` or contain `..` are rejected.
- Existing symbolic-link workspace paths are rejected.
- Existing non-directory workspace paths are rejected.
- Deletion is guarded by `destroy_for_state`; non-terminal states preserve the workspace for retry.

## Hooks

Hooks run through `bash -e -u -o pipefail -c <script>` with:

- current directory set to the issue workspace when using `run_hook_for`,
- `tokio::time::timeout` around process execution,
- captured stdout/stderr truncated to the configured output limit,
- `X0X_SYMPHONY_WORKSPACE_ROOT` and `X0X_SYMPHONY_WORKSPACE_PATH` set explicitly,
- `env_clear()` so the parent process environment is never forwarded wholesale.

Secret-like environment variable names ending in `_TOKEN`, `_KEY`, or `_SECRET` are denied unless the exact name is explicitly allow-listed in `WorkspaceConfig`.

## References

- Architecture: [`../design/symphony.md`](../design/symphony.md) §5.3
- Plan: [`../plan/implementation-plan.md`](../plan/implementation-plan.md) XSY-0005
