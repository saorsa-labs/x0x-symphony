# x0x-symphony-workspace

Workspace manager and hook execution for x0x-symphony.

This crate owns the M1 filesystem safety boundary: deterministic per-issue
workspace paths, root-containment checks, hook execution with timeout, and
explicit hook environment filtering.

Read the architecture first:

- [`../../docs/design/symphony.md`](../../docs/design/symphony.md)
- [`../../docs/plan/implementation-plan.md`](../../docs/plan/implementation-plan.md)
