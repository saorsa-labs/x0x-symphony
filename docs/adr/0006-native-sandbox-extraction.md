# ADR-0006 — Native sandbox extraction (`saorsa-sandbox`) with Linux Landlock launcher

**Status:** Accepted (2026-07-02)
**Deciders:** David Irvine (operator) + sandbox reviewer
**Context:** M4; XSY-0042 (Tier-2 native sandbox backends); XSY-0027 (Tier-1 external-tool wrappers); fluers WP-2 contract (D1–D4, banked `b199df6`)
**Related:** ADR-0005 (consent-gated dispatch), XSY-0039 (dispatch gate @ `6c02ae1`), XSY-0057 (macOS-native follow-up, filed with this ADR)

## Context

XSY-0042 calls for **native** (no-fork-of-external-tool) sandbox backends to
replace the Tier-1 wrappers shipped in XSY-0027 (`bwrap`, `landlock-restrict`,
`sandbox-exec`). The blocker was that native Landlock/cgroup/Seatbelt enforcement
requires raw syscalls/FFI = `unsafe`, which directly conflicts with the
workspace's immutable `unsafe_code = "forbid"` policy.

A plan (`docs/plan/xsy-0042-native-sandbox-plan.md`) presented three decisions
to a sandbox reviewer, who ruled on each (this ADR records those rulings and
their binding conditions).

### SOTA (researched 2026-07-02)

**Linux — clean winners:**

| Crate | Version | Downloads | License | Maintainer |
|-------|---------|-----------|---------|------------|
| `landlock` | 0.4.5 | 11.5M | MIT/Ap-2.0 | **l0kod** (Mickaël Salaün — Landlock kernel LSM author) |
| `cgroups-rs` | 0.5.0 | moderate | MIT/Ap-2.0 | Tim-Zhang et al. |

`landlock` provides a **safe** abstraction over the Landlock syscalls (fs +
network access control). `cgroups-rs` provides a safe abstraction over cgroup-v2
fs operations (resource bounding). Together they cover containment + resources
without forking an external binary. `landlock` is the model vetting case: written
by the subsystem's own kernel author.

**macOS — the gap:** no mature pure-Rust safe Seatbelt crate exists
(`seatbelt-rs` 0.1.0 = 15 downloads; `safe-shell` 0.1.2 = 36). Apple has
deprecated `sandbox_init` without documenting a replacement, so macOS-native is
a **research task**, not an implementation task. `sandbox-exec` remains what
Apple's own tooling and credible sandboxing projects (`ai-jail`) lean on.

## Decision

### (P) The `unsafe` policy principle — authorship, not transitive purity

Symphony forbids **symphony-authored** `unsafe`. Depending on a vetted crate
that encapsulates `unsafe` behind a safe public API is **permitted** — this is
the Rust ecosystem norm (std itself is `unsafe` inside) and is already how
`tokio`, `libc`, and `ring` are used. Refusing it would mean forking the entire
dependency tree. **The boundary is authorship of `unsafe`, not transitive purity
of the dependency graph.**

**Enforcement (the real gate):** `saorsa-sandbox` carries
`#![forbid(unsafe_code)]` at its crate root. The attribute is
compiler-enforced and **cannot** be bypassed by an `#[allow(unsafe_code)]`
further down. The `rg '\bunsafe\b'` grep is retained in CI as belt-and-braces,
but the `forbid` attribute is the authoritative gate.

**Permitted-crate list (the only crates whose internal `unsafe` this design
relies on for containment):**

| Crate | Version | Rationale (vetting bar) |
|-------|---------|-------------------------|
| `landlock` | `0.4` (pin to 0.4.x) | Maintained by the Landlock kernel LSM author (l0kod); 11.5M downloads; MIT/Ap-2.0; safe API |
| `cgroups-rs` | `0.5` (pin to 0.5.x) | Maintained; MIT/Ap-2.0; safe fs abstraction |
| `libc` | workspace | std's own dependency; pervasive Rust norm |
| `tokio` | workspace | async runtime; pervasive Rust norm |
| `ring` | (via signing) | audited crypto; pervasive Rust norm |

Vetting bar for additions to this list: **maintained, widely used, and
preferably authored by the subsystem owner** (the `landlock` case is the model).
Additions require an ADR amendment (escalation trigger #2).

### (L) Linux mechanism — internal launcher binary (L1)

**NOT (L2) audited unsafe enclave.** The decisive argument against L2:
`pre_exec` runs in the forked child of a multithreaded tokio process, where
**only async-signal-safe operations are legal**. It is one of the easiest places
in Rust to write undefined behavior that passes every test and fails under load.
An "audited unsafe enclave" is still symphony-owned `unsafe` in the most
safety-critical crate of the project, auditable only by someone who deeply
understands fork semantics. L2's single benefit (one fewer exec) is noise
against process-spawn cost for task execution.

**L1 design — internal `saorsa-sandbox-launcher` binary:**

1. Parent creates the cgroup-v2 leaf + sets cpu/memory/pids limits.
2. Parent spawns the launcher with a **synchronization pipe**.
3. Launcher **blocks on the pipe** before doing anything (this closes the
   spawn→cgroup race: the child does not proceed until the parent has placed it
   in the cgroup — which the `pre_exec` path only approximates).
4. Parent moves the launcher PID into the cgroup.
5. Parent releases the pipe.
6. Launcher **applies Landlock to itself** via the safe `landlock` crate API
   (`landlock_restrict_self`).
7. Launcher `exec`s the target command.

Symphony code stays **`unsafe`-free**; the only `unsafe` is inside the vetted
`landlock`/`libc` crates. The launcher is an **internal symphony binary** (a
compiled-in sibling resolved per condition below), **not** an external system
wrapper like `bwrap` — so this is genuinely "native", not Tier-1.

**L1 binding conditions (both mandatory):**

1. **Launcher integrity.** The launcher path is resolved from a
   **non-attacker-controllable location** — a compiled-in sibling of
   `current_exe()` or a workspace-internal `bin` — **never** from `PATH` and
   **never** from config that network-sourced content could influence.
2. **Fail-loud-degrade carries the XSY-0027 semantics.** If the launcher is
   missing, or a backend `probe()` fails, the daemon **refuses network-sourced
   work** (same as the unsupported-OS path). Degrading to unsandboxed execution
   is acceptable **only for local-sourced tasks**, and only with a loud
   `tracing::warn!`. A network-sourced task with no enforcing backend never
   executes (fail-closed, consistent with the `6c02ae1` dispatch gate).

### (M) macOS scope — split (M1)

**NOT (M2) macOS-native enclave now.** A 15-download crate is not a dependency
for a security boundary, and writing our own Seatbelt bindings now would
contradict decision (P) in the same breath as adopting it — M2 is internally
inconsistent with this ADR's own principle. Apple's deprecated-but-unreplaced
`sandbox_init` makes macOS-native a research task, not an implementation task.

**M1 — the honest acceptance split:**

- **macOS containment remains Tier-1 (`sandbox-exec`).** `docs/symphony/security.md`
  states this plainly (updated with this ADR). `sandbox-exec` is what Apple's
  own tooling and credible projects lean on.
- **XSY-0057 (macOS-native sandbox)** is filed with this ADR as a research
  follow-up, carrying the seatbelt-rs-maturity-wait / scoped-FFI / Apple-replacement-watch
  decision.
- **XSY-0042 is marked Linux-native-complete** with the macOS split recorded
  explicitly in the tracker. It is **not** claimed complete-as-originally-worded;
  the acceptance is split per the honesty rule (no capability claimed unless
  wired and tested).

### D1–D4 fluers contract (adopted at extraction)

- **D1 (LOCKED):** `wrap()` returns env **additions** over the caller allowlist,
  not a complete child env; collision = backend overrides caller (deliberate).
  The shared `wrap` ctx carries the caller's resolved allowlist **read-only** so
  conditional additions are cheap now, not retrofitted later.
- **D2:** `prepare(ctx) -> session` + `wrap(argv) -> cmd` + `session.shutdown()`
  split.
- **D3:** `probe()` per-backend fail-closed self-test (§5 of the plan).
- **D4:** cwd `Option<PathBuf>`, `None` = workspace root.

## Consequences

- **Positive:** Linux containment becomes native Landlock + cgroup-v2; resource
  limits bound forked descendants (Tier-1's per-process ulimit could not); zero
  symphony-authored `unsafe`; `#![forbid(unsafe_code)]` makes the policy
  compiler-enforced; the `spawn→cgroup` race is closed properly.
- **Negative / disclosed:** L1 adds one extra fork (launcher→target) per
  sandboxed run vs Tier-1's single fork — disclosed in the release annotation.
  macOS stays Tier-1. cgroup-v2 resource bounding needs unprivileged-cgroup
  delegation; without it Landlock containment holds but limits degrade to
  per-process (loud `warn!`). Landlock needs Linux ≥ 5.13.
- **Fluers:** consumes the same `saorsa-sandbox` crate at its WP-5 extraction;
  the fail-loud-degrade pattern is reused from fluers WP-2 (`b199df6`).

## Validation gates (the grep + attribute are both mandatory)

```
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
cargo check --workspace --all-targets
cargo nextest run --workspace
rg -n '\bunsafe\b' crates/saorsa-sandbox crates/x0x-symphony-runner-shell   # MUST be empty
```

The `#![forbid(unsafe_code)]` crate attribute is the authoritative gate; the
grep is belt-and-braces. `dispatch.rs` is untouched throughout (the `6c02ae1`
classification + 9 adversarial fail-closed tests intact). With the forbid
attribute + dispatch.rs-untouched constraints, this work stream sits **below**
standing-trigger #1 once this ADR is signed off — it runs to completion
merge-on-green without further holds.
