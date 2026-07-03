# XSY-0042 Plan — Native sandbox backends via saorsa-sandbox extraction

**Status:** DRAFT v2 for reviewer. Authorizes escalation triggers #2 (ADR) + #3
(security default). Operator chose "native sandbox." This plan resolves *how*,
and is **held for reviewer sign-off on two decisions before implementation**:
(L) launcher-binary vs audited unsafe-enclave for Linux; (M) macOS scope split.

---

## 1. The `unsafe` policy — honest resolution (revised after review)

**Tension:** native Landlock/cgroup requires applying restrictions to the child
before/around exec. The `landlock` crate exposes a **safe** API, but applying it
to *only the child* is the hard part: the obvious path needs `pre_exec`/`clone3`
= symphony-authored `unsafe`, violating `unsafe_code="forbid"`.

**What does NOT work (v1 overclaim, corrected):** "just depend on the safe
`landlock` crate and we're done." False — the parent still needs the child
restricted, and cgroup-attach-after-spawn races the child.

**Two honest forks for Linux — DECISION (L) for reviewer:**

- **(L1, recommended) Internal launcher helper binary.** A small symphony helper
  (`saorsa-sandbox-launcher`) does the self-restriction dance:
  1. Parent creates the cgroup-v2 leaf + sets cpu/memory/pids limits.
  2. Parent spawns the launcher with a synchronization pipe.
  3. Launcher **blocks on the pipe** before doing anything (closes the
     spawn→cgroup race).
  4. Parent moves the launcher PID into the cgroup.
  5. Parent releases the pipe.
  6. Launcher **applies Landlock to itself** via the safe `landlock` crate API.
  7. Launcher `exec`s the target command.
  - **Symphony code stays `unsafe`-free.** The only `unsafe` is inside the
    vetted `landlock`/`libc` crates (already how `tokio`/`ring` are used).
  - This is an **internal** launcher (symphony's own binary), **not** an external
    system wrapper like `bwrap` — so it genuinely is "native", not Tier-1.
  - Cost: one extra fork (launcher→target). Disclosed in §10.

- **(L2, alternative) Audited unsafe enclave.** A single `saorsa-sandbox-raw`
  sub-crate with a scoped `unsafe_code="allow"` that wraps `clone3`/`pre_exec`.
  Fewer forks, but reintroduces symphony-owned `unsafe` needing dedicated audit.

**Recommendation: L1.** It honors the forbid policy literally AND in intent, and
keeps all `unsafe` in upstream-vetted crates. The plan below assumes L1 unless
the reviewer prefers L2.

**Principle to record in the ADR:** symphony forbids **symphony-authored**
`unsafe`; depending on a vetted crate that encapsulates `unsafe` behind a safe
API is permitted (already how `tokio`/`ring` work). **No blanket carve-out.** If
L2 is chosen, the enclave is a single named, audited exception, not a precedent.

---

## 2. SOTA research findings (primary sources, fetched 2026-07-02)

### Linux — clear winners

| Crate | Version | Downloads | License | Maintainer | Verdict |
|-------|---------|-----------|---------|------------|---------|
| **`landlock`** | 0.4.5 | **11.5M** | MIT/Ap-2.0 | **l0kod** (Mickaël Salaün — Landlock kernel LSM author) | **USE.** Canonical, authoritative provenance, safe API over `landlock_create_ruleset`/`landlock_restrict_self`. ABI v7 (Linux 6.15). MSRV 1.71. https://docs.rs/landlock/latest/landlock/ |
| **`cgroups-rs`** | 0.5.0 | moderate | MIT/Ap-2.0 | Tim-Zhang et al. | **USE** for cgroup-v2 resource limits (CPU/mem/pids/freezer). Safe fs abstraction. https://docs.rs/cgroups-rs/latest/cgroups_rs/ |

`landlock` = filesystem + network access control (path-beneath rules, NetPort).
`cgroups-rs` = resource bounding. Together: containment + resource limits
without an external binary. Reference points: `sandlock-core` 0.8.4 (Landlock +
seccomp-bpf) confirms the direction; `ai-jail` 1.10.3 (bubblewrap/sandbox-exec)
confirms our *current* Tier-1 is also niche-SOTA — we're upgrading Linux, not
building from nothing.

### macOS — the gap (honest)

| Crate | Version | Downloads | Verdict |
|-------|---------|-----------|---------|
| `seatbelt-rs` | 0.1.0 | **15** | Too immature. No. |
| `safe-shell` | 0.1.2 | 36 | Too immature. No. |

crates.io search (`seatbelt`, `sandbox`) returns no mature pure-Rust safe macOS
Seatbelt crate. Native macOS = symphony FFI to `sandbox_init_with_parameters`
(deprecated C API, functional) = symphony `unsafe`, OR a scoped carve-out. See
§4 DECISION (M).

### Fluers alignment (WP-2 banked)

Fluers WP-2 at `b199df6`; `ProcessSandbox` trait slot holds C1–C4 semantics.
The **fail-loud-degrade pattern** (`tracing::warn!` before path-containment
fallback, caught in independent review) is **reused** on symphony's side (§6).

---

## 3. Architecture — extract `saorsa-sandbox` crate

```
crates/saorsa-sandbox/
  src/
    lib.rs          — re-exports
    trait.rs        — Sandbox, SandboxSession, CommandPlan, PreparedCommand, IssueSource (moved from runner-shell)
    wrapper.rs      — HostSandbox + Tier-1 external wrappers (bwrap/sandbox-exec) moved here
    landlock.rs     — NEW (Linux): native backend driver (parent side)
    cgroup.rs       — NEW (Linux): cgroup-v2 setup/teardown
    probe.rs        — NEW: per-backend probe() self-tests
    degrade.rs      — NEW: fail-loud backend preference resolution
  src/bin/
    saorsa-sandbox-launcher.rs  — NEW (L1): the self-restricting helper binary
  Cargo.toml        — [target.'cfg(target_os="linux")'.dependencies] landlock, cgroups-rs
                      unsafe_code = "forbid"  (inherits; NO allow anywhere)
```

`x0x-symphony-runner-shell` becomes a *consumer* (path dep now, crates.io at
M5/XSY-0035). Fluers consumes the same crate at its WP-5 extraction.

### D1/D2 reshape (banked fluers contract, done at extraction)

- **D1 (LOCKED):** `wrap()` returns env **addDITIONS** over caller allowlist, not
  complete child env; collision = backend overrides caller. Forward-note
  honored: shared wrap ctx carries caller's resolved allowlist **read-only**.
- **D2 (agreed shape):** `prepare(ctx) -> session` + `wrap(argv) -> cmd` +
  `session.shutdown()` split.
- **D3:** `probe()` per-backend (§5). **D4:** cwd `Option<PathBuf>`, None=workspace.

---

## 4. Platform backends — scope & the two decisions

### Linux (IN SCOPE) — native via DECISION (L) [L1 launcher assumed]

- **Containment:** launcher self-applies `landlock` `Ruleset` (path-beneath:
  workspace + explicit allow-paths; deny rest) before exec'ing target.
- **Resources:** parent creates cgroup leaf, sets limits, moves launcher PID in
  (race-free via the pipe block), tears down on `shutdown()`. Bounds **forked
  descendants** (Tier-1's per-process ulimit could not).
- **No external system tool forked.** The launcher is symphony's own binary.

### macOS — DECISION (M) for reviewer

**Honest statement:** XSY-0042's acceptance ("macOS Seatbelt implements Sandbox
without shelling out") is **not satisfiable** in this issue without either
symphony-authored `unsafe` (carve-out) or an immature dep. Therefore:

- **(M1, recommended) Amend XSY-0042 acceptance: Linux native now; macOS native =
  explicit follow-up issue.** macOS keeps Tier-1 `sandbox-exec` (works;
  `ai-jail`-validated). The follow-up carries the seatbelt-rs-wait / scoped-FFI
  decision. **XSY-0042 is NOT marked "complete"** — it's split: Linux done, macOS
  follow-up filed. This honesty preserves the "don't claim a capability unless
  wired and tested" rule.
- **(M2) Include an audited macOS Seatbelt unsafe enclave now.** Higher cost,
  broader review; unblocks full native on both platforms in one issue.

**Recommendation: M1.** Defer macOS native to a scoped decision rather than rush
an unsafe enclave or bet on a 15-download crate.

---

## 5. `probe()` design — fail-closed self-test

Answers "is this backend actually *enforcing*?" not just "present."

- **Linux Landlock:** create a `Ruleset`, query returned ABI. ABI ≥ 1 ⇒
  supported; ABI 0 / `RulesetError` ⇒ `Unsupported`. Cached at startup.
- **cgroup-v2:** check mounted hierarchy at `/sys/fs/cgroup` + write permission
  into parent; document the unprivileged-delegation prerequisite
  (`systemd-run --scope`/`User.slice`).
- **macOS (Tier-1):** existing `sandbox-exec` presence check.

---

## 6. Fail-loud-degrade (reused from fluers WP-2)

Backend preference order, **explicit `tracing::warn!` before every downgrade**:

- **Linux:** native (Landlock+cgroup, L1) → Tier-1 bwrap → Tier-1
  landlock-restrict → path-containment (`warn!`) → **refuse** if
  `source == NetworkSourced` and no enforcing sandbox.
- **macOS:** Tier-1 sandbox-exec → path-containment (`warn!`) → **refuse** for
  network-sourced.

**Invariant for reviewer:** a network-sourced task with no enforcing backend is
**never executed** (fail-closed, consistent with the 6c02ae1 dispatch gate).
Native sandbox is an *enforcement upgrade*, never a trust downgrade.

---

## 7. Testing strategy

- **Unit (host):** config parsing, preference-order resolution, D1 env-additions
  semantics, D2 split, fail-loud-degrade logic, launcher pipe-protocol parsing.
- **probe tests:** `#[cfg(target_os="linux")]` + runtime capability; CI Linux
  (kernel ≥5.13) actually creates a ruleset, asserts ABI ≥ 1.
- **Containment test (Linux, integration):** child reads file **outside** allow
  → denied (EACCES) with Landlock; reads inside workspace → succeeds. Proves
  enforcement, not just loading.
- **cgroup test (Linux):** child forks beyond `pids.max` → grandchildren denied.
  Proves descendant bounding (the Tier-1 gap).
- **launcher race test:** assert target exec does not begin until parent has
  moved launcher into cgroup (pipe ordering).
- **No existing test weakened.** Tier-1 tests move with the code, keep passing.

---

## 8. ADR-0006 (BEFORE implementation — escalation trigger #2)

Records, for reviewer approval *then* implementation:
1. DECISION (L) outcome (L1 launcher vs L2 enclave) + the
   safe-dependency principle (symphony forbids symphony-authored unsafe; vetted
   deps that encapsulate unsafe are permitted; enclave, if any, is a named
   audited exception, not precedent).
2. DECISION (M) outcome (M1 split vs M2 macOS-now).
3. D1/D2 fluers contract adoption at extraction.
4. The launcher is an internal symphony binary (not an external wrapper).

ADR-0006 is written and approved **before** any extraction code lands.

---

## 9. Validation gates (per AGENTS.md, in order)

```
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
cargo check --workspace --all-targets
cargo nextest run --workspace
```

Plus **mandatory grep** (L1): `rg -n '\bunsafe\b' crates/saorsa-sandbox
crates/x0x-symphony-runner-shell` must be **empty** (symphony code stays
unsafe-free; unsafe lives only in the deps). If L2 chosen, the enclave crate is
the sole non-empty result and is named in the ADR. `dispatch.rs` untouched
(6c02ae1 classification + 9 adversarial tests intact).

---

## 10. Disclosed boundaries for the release annotation

- L1 adds one extra fork (launcher→target) per sandboxed run vs Tier-1's
  single fork — disclosed.
- macOS remains Tier-1 (`sandbox-exec`) under M1; native macOS = follow-up.
- cgroup-v2 resource bounding needs unprivileged-cgroup-delegation; without it,
  Landlock containment holds but limits degrade to per-process (loud `warn!`).
- Landlock needs Linux ≥ 5.13; best-effort compatibility via the crate.

---

## 11. Sequencing (each step merge-on-green)

1. **ADR-0006** (after reviewer approves L + M). — gates everything.
2. Extract `saorsa-sandbox` crate (move trait + Tier-1 wrappers; re-point
   runner-shell). Green. — pure refactor.
3. D1/D2 reshape on the moved trait. Green. — additive API.
4. Linux native backend + launcher (L1) + `probe()` + fail-loud-degrade +
   containment/cgroup/race tests. Green. (L2 instead if chosen.)
5. File macOS-native follow-up (M1). Update operator/security docs + Obsidian
   mirror. Update issues.jsonl XSY-0042 → review, **split acceptance** recorded.

---

## Decisions requested from reviewer (block implementation)

- **(L)** L1 internal launcher (recommended, zero symphony unsafe) **or** L2
  audited unsafe enclave?
- **(M)** M1 split (Linux now, macOS follow-up — recommended) **or** M2 macOS
  native enclave now?
- **(P)** Accept the principle: *symphony forbids symphony-authored `unsafe`;
  vetted deps that encapsulate `unsafe` (landlock/libc/tokio/ring) are
  permitted* — i.e. the dependency graph is **not** in scope for the forbid?

Until these are answered, XSY-0042 stays held. No code lands.
