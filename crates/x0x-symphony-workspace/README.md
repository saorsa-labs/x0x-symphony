# x0x-symphony-workspace

Contained workspace manager for x0x-symphony.

This crate implements deterministic per-issue workspaces under a configured
root, defensive path containment, and hook execution with timeouts. Identifier
sanitization lives in the dedicated `containment` module and rejects unsafe
inputs instead of rewriting them.
