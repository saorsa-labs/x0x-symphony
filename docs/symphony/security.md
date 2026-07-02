# x0x-symphony — Security posture and sandbox profiles

This document states x0x-symphony's security posture for the M1–M3
window and the M2 sandbox-profile layer added by XSY-0027. The original
interim rules remain the baseline: local operator-controlled work can run
without a configured sandbox, but network-sourced dispatch is default-off
through M3 and becomes fail-closed once that source exists. The
architecture document [`../design/symphony.md`](../design/symphony.md)
§11 remains the authoritative security model.

---

## Threat model summary

During M1–M3, a runner is a **child process with repo-write and network
access**. There is no sandbox. Containment rests on two controls:

1. **Workspace path containment** — the runner executes only inside a
   per-issue workspace directory under the configured `workspace.root`.
   Issue identifiers are sanitized against a whitelist, paths are
   canonicalized and prefix-verified, and symbolic links that escape the
   root are rejected at creation and re-checked at destroy. This control
   lands with the workspace manager (XSY-0005 / plan §4.1).
2. **Environment allow-list / deny-list** — hook and runner environments
   start from empty. Only variables declared in `WORKFLOW.md` are added.
   Secrets matching `*_TOKEN`, `*_KEY`, or `*_SECRET` are deny-listed
   unless explicitly allow-listed. This control lands with the runner
   (XSY-0004) and workspace hooks (XSY-0005 / plan §4.1).

These are the primary and secondary boundaries. XSY-0027 adds a tertiary
host-sandbox boundary when `[runner.sandbox]` is configured; omitting the
block intentionally preserves the local-development unsandboxed behavior.

---

## The four interim rules

> Until sandbox profiles land (M4), a runner is a child process with
> repo-write and network access, contained only by workspace pathing.
> Therefore: (1) x0x-symphony executes **only** issues from the local
> git-committed backlog that the operator controls — no network-sourced
> work is dispatched before M3, and at M3 dispatch is hard-gated on
> signature verification + trust level (XSY-0039); (2) hook and runner
> environments are allow-list only, secrets deny-listed by default;
> (3) the operator vouches for every command configured in WORKFLOW.md
> — treat it with the same care as CI config; (4) tasks labelled
> `security-sensitive` are refused outright until XSY-0028.

Per-rule controlling issues:

1. **Local-backlog-only execution.** The M1 `git_jsonl` tracker reads only
   `issues/issues.jsonl` — the local, operator-controlled, git-committed
   backlog. No code path exists to dispatch work sourced over the network.
   At M3 the `x0x_crdt` adapter may *list* network-sourced issues, but the
   orchestrator's execute path is hard-gated on XSY-0020 (ML-DSA-65
   signature verification) and XSY-0022 (trust level), tracker-enforced
   by XSY-0039. Until that gate is wired, network issues are listed but
   never dispatched.
2. **Environment allow-list / deny-list.** Runner and hook environments
   are constructed from empty plus an explicit allow-list; the deny-list
   blocks `*_TOKEN` / `*_KEY` / `*_SECRET` unless overridden. Implemented
   in the shell runner (XSY-0004) and workspace hooks (XSY-0005).
3. **Operator vouches for WORKFLOW.md.** Every command the orchestrator
   runs comes from `WORKFLOW.md`, resolved to an argv array — never
   through a shell, never with issue fields interpolated into argv. The
   operator who commits `WORKFLOW.md` is the trust root, exactly as with
   CI configuration.
4. **`security-sensitive` label refused.** Any issue carrying the
   `security-sensitive` label is refused outright by the orchestrator
   until XSY-0028 lands (Pinned identity + human approval step). There is
   no partial handling in the interim window.

---

## What this explicitly is NOT

This posture is **not**:

- **A sandbox when `[runner.sandbox]` is absent.** Local development may
  still opt out by omitting the block. When a sandbox block is present,
  the shell runner prepares the structured command plan into a wrapped command
  before process spawn and preserves the existing env-clear, stdio, timeout,
  and process group layers.
- **Signature verification.** Claims and handoffs are *not* signed or
  verified during M1–M2. ML-DSA-65 signing arrives with XSY-0020 at M3.
- **Trust-gated dispatch.** There is no trust-level evaluation before
  M3. All dispatched work is local and operator-controlled, so the trust
  gate is not yet exercised.

**Network-sourced work is impossible before M3.** The `git_jsonl` tracker
(XSY-0003) has no network code path; it reads only the local
operator-controlled repo. At M3 the `x0x_crdt` adapter (XSY-0019)
introduces network-sourced issues, but dispatch is hard-gated on verified
signature + trust level (XSY-0039) from the moment that path exists.

---

## Sandbox profiles (M2)

The shell runner accepts an optional `[runner.sandbox]` / `runner.sandbox:`
block. If omitted, behavior is unchanged and local work runs unsandboxed.
If present, the runner resolves a backend at construction time, prepares a
`CommandPlan` into a `WrappedCommand` plus `SandboxSession`, then builds
`tokio::process::Command` and applies the existing env-clear, stdio-pipe,
timeout, and process-group layers.

Profiles:

| Profile | Filesystem | Network | Secrets |
|---------|------------|---------|---------|
| `read-only` | Workspace mounted read-only; rest of host read-only where the backend supports it | Denied | Denied (`~/.ssh`, `~/.x0x`, `~/.aws`, `~/.config/gcloud`, `~/.gnupg`, browser profiles, plus configured denies) |
| `repo-write` | Workspace writable; rest read-only/masked | Configured LLM/API egress allow-list | Denied by default |
| `no-network` | Workspace writable; rest read-only/masked | Denied | Denied by default |
| `full-dev` | Workspace writable; broad host read/write where supported | Unrestricted | Accessible; use only for trusted, pinned agents |
| `ci-only` | Workspace writable; rest read-only/masked | CI/registry allow-list (GitHub, crates.io, configured registry) | Only CI-scoped secrets the operator explicitly passes |

Backend selection:

| Platform | `backend = auto` order | Notes |
|----------|------------------------|-------|
| Linux | `srt` → `bwrap` → `landlock-restrict` → `none` | Firejail was deliberately replaced with Bubblewrap. Bubblewrap provides filesystem, PID, and network namespace isolation, but domain-level egress allow-lists require an outer policy engine such as `srt`; when Bubblewrap is the effective backend, egress allow-list entries are advisory metadata rather than DNS firewall rules. |
| macOS | `srt` → `/usr/bin/sandbox-exec` → `none` | `sandbox-exec` enforces filesystem and coarse network operations from generated SBPL. Domain allow-lists are not DNS-specific. |
| Windows | `none` | Tier 1 has no Windows host sandbox; non-local dispatch must fail closed. |

`on_unavailable` controls only local work: `warn` logs and runs the
unwrapped command, while `fail-closed` refuses to spawn. Network-sourced
work is always fail-closed regardless of this setting; a resolved
`backend = none` is not enforceable for `IssueSource::NetworkSourced`.
This preserves the M2/M3 rule that network dispatch remains default-off
and, once introduced, cannot use an unavailable sandbox as an escape hatch.

Resource limits are Tier-1 best effort. Linux wraps sandboxed commands in
`systemd-run --user --scope` when CPU or memory limits are configured and
`systemd-run` is available. macOS uses shell `ulimit` / rlimit inheritance;
that is a per-process mechanism rather than a cgroup-scoped boundary, so
forked children are not bounded as strongly as on Linux. Proper native
resource enforcement is tracked for M4 Tier 2.

Every sandbox exposes a `probe()` self-test that returns a structured
`ProbeReport` for write-outside-workspace, secret-read, host-PID, and
non-allowlisted-network checks. Checks can be `not-applicable` when a
backend, platform primitive, or probe dependency is absent, but the report
always records each check explicitly.

---

## Future hardening

The following issues extend or supersede this posture, in milestone order:

| Issue | Milestone | What it adds |
|-------|-----------|--------------|
| [XSY-0020](../../issues/issues.jsonl) | M3 | ML-DSA-65 signing + verification of claim and handoff payloads |
| [XSY-0022](../../issues/issues.jsonl) | M3 | Trust-gated dispatch: rejects non-trusted agents on sensitive tasks |
| [XSY-0039](../../issues/issues.jsonl) | M3 | Dispatch gate: orchestrator refuses network-sourced issues without verified signature + trust |
| [XSY-0027](../../issues/issues.jsonl) | M4 | Sandbox profiles (Bubblewrap / sandbox-exec) — extends *this file* with profile mapping |
| [XSY-0028](../../issues/issues.jsonl) | M4 | Sensitive-task gates: Pinned identity + human approval step |

The four rules above remain as the baseline contract; configured sandbox
profiles layer additional defense-in-depth on top. Tier 2 replaces the
external-tool wrappers with native no-Node backends.
