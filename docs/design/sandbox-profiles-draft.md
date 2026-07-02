> **DRAFT — session-lead-approved design input for XSY-0027, not yet reviewed/committed by the implementing team.**
> **Supersedes `docs/design/symphony.md` §11's `firejail` reference (use `bubblewrap` instead).**
> This document is untracked design input. The XSY-0027 implementer should review, refine, and commit it (or a revision) as part of their PR. It has not been verified against a build.

# x0x-symphony runner sandboxing — design proposal (XSY-0027)

## 0. Provenance: verified vs assumed

Verified by reading the code and docs:

- `crates/x0x-symphony-runner-shell/src/runner.rs`, `src/env.rs`, `src/lib.rs`
- `crates/x0x-symphony-workspace/src/containment.rs`
- `docs/design/symphony.md` §5.2 (Runner), §5.3 (Workspace), §11 (Security model)
- `docs/symphony/security.md` (interim pre-sandbox posture)
- `issues/issues.jsonl`: XSY-0027, XSY-0028, XSY-0038 (+ referenced XSY-0020/0022/0039)

Verified from current (2026) primary web sources (cited in §9). Where a fact came from a
secondary blog rather than a primary doc it is marked "reported" inline.

Assumed (flag for the implementer to confirm): the exact set of harnesses run in production
(codex, claude_code, kimi, glm, minimax, pi presets over `shell`); that operators are willing
to install one external binary (`srt` or `bubblewrap`) on Linux; that the LLM-API egress
endpoints per harness are known at config time.

## 1. Where the runner stands today

`ShellRunner::command_for_session` (runner.rs) builds a `tokio::process::Command`:

```rust
let mut command = Command::new(&self.spec.command);
command
    .args(&self.spec.args)
    .current_dir(&sess.workspace_path)
    .env_clear()
    .envs(child_env)                 // allow-list; *_TOKEN/_KEY/_SECRET denied unless opted in
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
configure_process_group(&mut command);   // process_group(0) on unix
```

The turn timeout escalates to `SIGKILL` on the whole process group (`kill_process_group`
→ `kill(Pid::from_raw(-pgid), SIGKILL)`). The workspace crate (`containment.rs`) does
rigorous path containment: identifiers sanitized against `[A-Za-z0-9._-]`, canonicalized and
prefix-verified against a stored canonical root, symlink/alias escapes rejected at create and
re-checked at destroy, Windows reserved device names blocked.

**That is the entire boundary.** The child inherits the daemon's full filesystem reach and full
network. Of the five goals below, only a weak form of goal 1 holds — writes land in `cwd` by
convention, not by enforcement — and goals 2–5 are unmet.

§11 already commits to five profile names (`read-only`, `repo-write`, `no-network`, `full-dev`,
`ci-only`), enforced via a host sandbox, with the profile declared on the issue and the
orchestrator refusing to dispatch a task whose required profile cannot be enforced. XSY-0027 is
"the shell runner takes a `Sandbox` parameter" implementing exactly that. This proposal keeps
the five names and the refusal semantics, and changes only the Linux primitive: **bubblewrap
instead of firejail** (rationale in §8).

### The five goals

1. **FS write-confinement** to the workspace.
2. **FS read-confinement** away from secrets (`~/.ssh`, `~/.x0x` keys, cloud creds, browser
   profiles).
3. **No process escape / no killing other processes.**
4. **Resource limits** (CPU / memory / disk / process count).
5. **Egress restriction** to an allowlist of API endpoints (the child is itself an AI coding
   agent that *needs* network to its own LLM API — "no network" is the wrong default for the
   standard profile).

## 2. Comparison of viable approaches

Confinement columns rate each goal: ✓ strong / ◐ partial / ✗ none.

| Approach | Platforms | 1 write | 2 read | 3 no-escape | 4 rsrc | 5 egress | Ops cost | Maturity |
|---|---|---|---|---|---|---|---|---|
| **Anthropic sandbox-runtime (`srt`)** wrapping the child | macOS (Seatbelt) + Linux (bwrap) | ✓ | ✓ | ✓ (bwrap PID ns + seccomp) | ✗ (no cgroup/rlimit) | ✓ (proxy, domain allowlist) | Low, but **+Node.js runtime** dep + host proxy processes | New (2026), Anthropic-maintained; same tech the child harnesses use |
| **Native bubblewrap (Linux) + sandbox-exec/Seatbelt (macOS)**, Rust-built | macOS + Linux | ✓ | ✓ | ✓ (bwrap `--unshare-pid`; Seatbelt `deny signal`) | ◐ (add cgroups/rlimit) | ◐ (needs a proxy or firewall for domain-level; net-namespace is all-or-nothing) | Medium; bwrap must be installed on Linux | High — bubblewrap (Flatpak) + Seatbelt (App Store) both battle-tested |
| **Landlock** (Rust `landlock` crate) | Linux only (≥5.13 FS, ≥6.7 net) | ✓ | ✓ | ✗ (no signal/PID restriction) | ✗ | ◐ (TCP **port**-based only, not domain) | Very low (in-process, no external binary) | High crate (0.4.5, up to ABI v7 / Linux 6.15), but scope-limited |
| **Delegate to child's own sandbox flags** (`codex --sandbox workspace-write`, Claude Code sandbox) | macOS + Linux (+ Codex Windows) | ✓ | ◐ | ◐ | ✗ | ◐ (Codex net-off by default; Claude proxy allowlist) | Very low | High, but **only** for those two harnesses; a generic `shell` preset (kimi/glm/pi) has no such flag |
| **firejail** (§11's original pick) | Linux only | ✓ | ✓ | ◐ | ◐ (rlimit, cgroup) | ◐ | Medium; **setuid-root binary** = its own attack surface, recurring CVEs | Mature but security-fraught |
| **Rootless podman / Docker** | macOS (VM) + Linux | ✓ | ✓ | ✓ | ✓ (cgroups) | ✓ (network policy) | **High** — daemon/VM, image builds, bind-mount plumbing; violates "no mandatory Docker" | Very high |
| **microVM** (Firecracker / krunvm) | Linux (macOS via krunkit) | ✓ | ✓ | ✓ | ✓ | ✓ | Highest — kernel/rootfs mgmt, per-task boot latency | High but heavy |
| **Current: workspace pathing + env allowlist** | all | ◐ (cwd only, unenforced) | ✗ | ✗ | ✗ | ✗ | none | shipped |

Two structural facts drive the recommendation:

- **Landlock alone is insufficient.** It covers filesystem (goals 1/2) and coarse TCP-**port**
  restriction, but it does **not** restrict signals or process visibility (goal 3), has **no**
  resource limits (goal 4), and its network control is by port not domain (goal 5 needs a proxy
  regardless). Good as a *fallback* FS layer, not as the primary boundary.
- **`srt` is the cheapest way to get strong 1+2+3+5 cross-platform**, because it is purpose-built
  for "confine an arbitrary process, non-container, macOS+Linux" and internally *is* the
  bubblewrap + Seatbelt + seccomp + egress-proxy stack you would otherwise hand-build. Its cost
  is a Node.js runtime dependency and host-side proxy processes — and it gives goal 5 (domain
  egress allowlist) essentially for free, which the native path makes you build.

## 3. Recommended architecture

**A per-platform `Sandbox` abstraction in `x0x-symphony-runner-shell`, layered, fail-closed for
network-sourced work.**

### 3a. Trait + backend selection

Add a `sandbox` module:

```rust
/// Whether a backend can enforce a profile on this host.
pub enum Enforcement { FullyEnforced, Partial, Unavailable }

pub struct SandboxContext {
    pub workspace_path: PathBuf,   // the canonicalized per-issue workspace (goal 1 anchor)
    pub profile: Profile,
    pub egress: Vec<String>,       // domain allowlist for *-network profiles
    pub limits: ResourceLimits,
}

pub trait Sandbox: Send + Sync {
    /// Rewrite the child argv into a sandboxed argv, or error if this backend
    /// cannot enforce `ctx.profile` on this host.
    fn wrap(&self, argv: &[String], ctx: &SandboxContext) -> Result<Vec<String>>;

    /// Startup self-test: prove the profile is actually enforced (see §5).
    fn probe(&self, profile: &Profile) -> Result<Enforcement>;
}

pub enum Backend { Auto, Srt, Bubblewrap, Seatbelt, Landlock, None }
```

`command_for_session` changes from `Command::new(&spec.command).args(&spec.args)` to:

```rust
let argv = self.sandbox.wrap(&full_argv, &sandbox_ctx)?;   // full_argv = [command, args...]
let mut command = Command::new(&argv[0]);
command.args(&argv[1..]) /* …existing env_clear/envs/current_dir/stdio… */;
configure_process_group(&mut command);
```

Everything else stays. The sandbox is additive; `process_group(0)` + `SIGKILL` still work
because the wrapper (`srt` / `bwrap` / `sandbox-exec`) becomes the process-group leader and the
existing PG-kill reaps the whole subtree.

**`Backend::Auto` resolution per OS:**

- **Linux:** `srt` if on PATH, else native **bubblewrap** (`--unshare-pid`, `--unshare-net` or
  proxy, `--ro-bind` system paths, `--bind` workspace, `--die-with-parent`,
  `PR_SET_NO_NEW_PRIVS`), else **Landlock** best-effort as a reduced-capability fallback
  (FS-only; no egress control ⇒ usable only for `no-network` / `read-only` profiles).
- **macOS:** `srt` if on PATH, else native **sandbox-exec** with a generated Seatbelt profile
  (the same mechanism Codex, Claude Code, and `srt` all use). sandbox-exec prints a
  deprecation warning but is still shipped by Apple and depended on by every current agent
  harness — treat "deprecated" as cosmetic, not removed.
- **Windows:** `Backend::None`. Document-degraded: local operator work runs unsandboxed;
  **network-sourced work is refused** (`Enforcement::Unavailable`).

**Recommended default:** adopt `srt` as the default wrapper where available; native
bubblewrap/Seatbelt as the no-Node hardening path. Rationale: smallest strong step to unblock
M4; the one primitive that delivers goal 5 (domain egress) without writing a proxy; the same
isolation the child harnesses already trust.

**Always layer the child's own flags on top** (defense-in-depth, near-zero cost): the `codex`
and `claude_code` presets should additionally pass `--sandbox workspace-write` / Claude's
sandbox settings. The symphony-level OS sandbox is the *enforcing* boundary (so a generic
`shell` preset with no such flag is still contained); the child flag is belt-and-suspenders.

### 3b. The five profiles, concretely

"secrets" = `~/.ssh`, `~/.x0x`, `~/.aws`, `~/.config/gcloud`, `~/.gnupg`, `~/.netrc`, browser
profile dirs, and anything matching the existing `*_TOKEN` / `*_KEY` / `*_SECRET` env denylist
(the FS deny complements the env deny already in `env.rs`).

| Profile | FS write | FS read | Network egress | Resource caps | Use |
|---|---|---|---|---|---|
| `read-only` | `/tmp` scratch only | workspace + system libs; **deny secrets** | none | tightest | review / analysis tasks |
| `repo-write` **(default)** | workspace only | workspace + system libs; **deny secrets** | LLM API allowlist only | standard | coding-agent tasks |
| `no-network` | workspace only | workspace + system libs; **deny secrets** | **none** | standard | offline / air-gapped tasks |
| `full-dev` | workspace + build caches (`~/.cargo`, `~/.npm`, `~/.rustup`) | broad; **deny secrets** | LLM API + package registries allowlist | relaxed | tasks needing dependency fetch |
| `ci-only` | workspace | workspace + system libs | none (or CI endpoints only) | tightest | build / test execution |

The profile is declared on the issue (a `sandbox:<profile>` label, or the issue's
required-profile field) and defaults to `repo-write` for network-sourced coding work — matching
§11's "profile declared on the issue."

Concrete mapping to the `srt` config shape (the native backends map the same intent to Seatbelt
directives / bwrap bind-mounts):

```jsonc
// repo-write (default)
{
  "filesystem": {
    "denyRead":  ["~/.ssh", "~/.x0x", "~/.aws", "~/.config/gcloud", "~/.gnupg", "~/.netrc"],
    "allowRead": ["<workspace>"],          // system paths (/usr,/lib,…) remain readable
    "allowWrite": ["<workspace>", "/tmp"],
    "denyWrite":  []
  },
  "network": { "allowedDomains": ["api.anthropic.com", "api.openai.com"], "deniedDomains": [] }
}
```

`no-network` = same filesystem block, `"allowedDomains": []`. `read-only` = `allowWrite: ["/tmp"]`
only. `full-dev` = add `~/.cargo`, `~/.npm`, `~/.rustup` to `allowWrite` and the registry hosts
(`crates.io`, `static.crates.io`, `registry.npmjs.org`, …) to `allowedDomains`. `ci-only` =
`allowWrite: ["<workspace>"]`, `allowedDomains: []`, tightest limits.

### 3c. RunnerSpec / WORKFLOW.md expression

Add a `[runner.sandbox]` block that resolves into a new `SandboxSpec` field on `RunnerSpec`:

```toml
[runner.sandbox]
backend  = "auto"          # auto | srt | bubblewrap | seatbelt | landlock | none
profile  = "repo-write"    # default; an issue's sandbox:<profile> label overrides
egress   = ["api.anthropic.com", "api.openai.com"]   # domain allowlist for *-network profiles
on_unavailable = "refuse"  # refuse | degrade  (see §3d)

[runner.sandbox.limits]
memory_mb   = 4096
cpu_seconds = 3600
max_procs   = 512
disk_mb     = 2048
```

An issue-level `sandbox:<profile>` label overrides `profile`; the orchestrator maps the label to
the required `Profile` and threads it into `SessionContext` (which already carries
`workspace_path` and `env_allowlist`). The env allowlist / secret-deny in `env.rs` stays and
composes with the FS secret-deny.

### 3d. Fallback behavior (the key operator decision)

Two-tier, decided by work **provenance**, not by config alone:

- **Network-sourced work (M3+ `x0x_crdt` issues): fail-closed, always.** If
  `sandbox.probe(profile) != FullyEnforced`, the orchestrator **refuses to dispatch** and
  surfaces the reason. `on_unavailable = "degrade"` is *ignored* for network-sourced issues.
  This is the direct implementation of §11's "refuses to dispatch a task whose required profile
  cannot be enforced by the available runner."
- **Local operator-controlled work (git_jsonl backlog): `on_unavailable` governs.** Default
  `refuse`; the operator may set `degrade` to run unsandboxed with a loud warning, because the
  interim posture (`docs/symphony/security.md`) already accepts unsandboxed local work the
  operator vouches for. This preserves today's workflow for operators on Windows or on kernels
  without the required primitives, while making the strong path the default. Windows falls into
  this tier for local work and is refused for network-sourced work.

## 4. Resource limits (goal 4) — backend-independent

`srt` does **not** do resource limits, so this layer is symphony's regardless of backend:

- **Linux:** transient cgroup v2 — `systemd-run --scope -p MemoryMax=… -p CPUQuota=… -p
  TasksMax=…` when systemd is present, else a direct cgroup write, else `setrlimit` via
  `Command::pre_exec`. `disk_mb` is enforced via the workspace filesystem (quota or a
  size-checked tmpfs mount) rather than a per-process rlimit.
- **macOS:** `setrlimit` only (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`, `RLIMIT_FSIZE`) via
  `pre_exec`. **macOS has no cgroup-equivalent hard memory cap**, so memory limiting there is
  best-effort `RLIMIT_AS`. Document this as a known gap.

## 5. Probe / self-test matrix (§4 gate item 3 made concrete)

At startup (and on config change), `sandbox.probe(profile)` must run a child under the resolved
backend+profile and observe each of the following; any failure downgrades the result below
`FullyEnforced` and blocks network-sourced dispatch:

| Check | Goal | Expected observation |
|---|---|---|
| Write a file outside the workspace (`$HOME/x0x-probe`) | 1 | `EPERM` / denied |
| Read a secret path (`~/.ssh/known_hosts` or a seeded fixture) | 2 | `EPERM` / denied |
| Send a signal to a known host PID (e.g. the daemon) / enumerate host PIDs | 3 | fails, or host PIDs invisible (PID namespace) |
| Connect to a non-allowlisted host (e.g. `example.net:443`) | 5 | blocked by proxy/namespace |
| Connect to an allowlisted host (e.g. `api.anthropic.com:443`) | 5 | permitted (for `*-network` profiles) |
| Resource limits attached (query cgroup / getrlimit) | 4 | limits present and non-default |

Store the probe result per (backend, profile, host). Landlock backend will report `Partial`
(fails the signal/PID and resource checks) ⇒ only `no-network`/`read-only` profiles can reach
`FullyEnforced` under it, and even then goal 3 is unmet — so Landlock alone must **not** clear
the network-sourced gate.

## 6. M4 gate — what "enable network-sourced dispatch" minimally requires

Enabling network-sourced dispatch is the **conjunction** of the M3 trust chain and an enforced
sandbox. All must hold before the orchestrator's execute path accepts a network-sourced issue:

1. **XSY-0020** ML-DSA-65 signature verification on the claim/handoff (the pre-existing hard
   gate) and **XSY-0039** dispatch gate wired.
2. **XSY-0022** trust-level gate satisfied for the task's sensitivity.
3. **XSY-0027 probe = `FullyEnforced`** for the issue's required profile, per the §5 matrix.
4. **Egress allowlist active and non-empty** for any `*-network` profile (empty allowlist under a
   network profile is a misconfiguration → refuse).
5. **Fail-closed:** if 3 or 4 fail, the issue is refused, not degraded.
6. **XSY-0028** for `security-sensitive` labels: `TrustLevel == Pinned` + a signed
   `ApprovalEvent`, on top of all the above.

Minimal viable gate = items 1–5 with the `repo-write` profile probing `FullyEnforced` on the
operator's OS; item 6 applies only to the `security-sensitive` subset. Practically: **M4 can flip
network-sourced dispatch on as soon as the `repo-write` self-test passes on the operator's OS and
the M3 signature/trust gates are wired** — the sandbox is the last of the three legs, not an
independent research project.

## 7. Implementation size estimate

Both tiers keep the existing runner/workspace/env code and add a `sandbox` module.

**Tier 1 — `srt`-delegating default (recommended first landing):**

| Item | LOC |
|---|---|
| Sandbox trait + config types + `SandboxSpec` on `RunnerSpec` + WORKFLOW.md parse | ~250 |
| `srt` backend: generate per-profile JSON, resolve `srt` on PATH, wrap argv, map 5 profiles | ~250 |
| Startup probe / self-test harness (the §5 checks) | ~200 |
| Resource-limits layer (systemd-run/cgroup + setrlimit pre_exec) | ~250 |
| Wiring into `command_for_session` + orchestrator refuse-path | ~150 |
| Tests (5 profiles × macOS/Linux + refusal + probe) | ~500 |
| **Subtotal** | **~1,300–1,600 LOC + a documented Node.js/`srt` prerequisite** |

**Tier 2 — native no-Node backends (follow-up hardening):**

| Item | LOC |
|---|---|
| Native Seatbelt profile generation (macOS) | ~250 |
| Native bubblewrap arg builder (Linux), incl. proxy or net-namespace egress | ~350 (+~400 if building an own domain-allowlist HTTP CONNECT proxy) |
| Landlock fallback backend (`landlock` crate, best-effort, FS-only) | ~200 |
| Extra tests | ~400 |
| **Subtotal** | **~1,200–1,800 additional LOC** |

**Recommendation:** land Tier 1 to unblock M4 (smallest strong step, gets goal 5 for free), then
add Tier 2 to drop the Node dependency and give a native path on hosts that won't install `srt`.
XSY-0027's stated acceptance ("five profiles implemented and tested on macOS and Linux;
refusal-to-run on unsupported OS; no production unwrap/expect/panic") is satisfiable by Tier 1
alone **if** the `srt` prerequisite is acceptable; if the acceptance intends zero external runtime
deps, Tier 1 + the native macOS/Linux backends of Tier 2 are both needed.

## 8. Correction to §11 / security.md

`docs/design/symphony.md` §11 and `docs/symphony/security.md`'s "Future hardening" table name
`firejail` as the Linux primitive. Replace it with **bubblewrap** (unprivileged, no setuid-root,
the choice of Flatpak, Codex, Claude Code, and `srt`). firejail's setuid-root design is a
recurring-CVE liability and the wrong default for a security boundary. The five-profile model and
the refusal semantics are otherwise sound and should be kept verbatim.

## 9. Sources

- Anthropic sandbox-runtime — https://github.com/anthropic-experimental/sandbox-runtime
- Anthropic: Making Claude Code more secure with sandboxing — https://www.anthropic.com/engineering/claude-code-sandboxing
- Claude Code sandboxing docs — https://code.claude.com/docs/en/sandboxing
- OpenAI Codex sandbox docs — https://github.com/openai/codex/blob/main/docs/sandbox.md and https://developers.openai.com/codex/concepts/sandboxing
- landlock Rust crate (0.4.5, ABI ≤ v7 / Linux 6.15) — https://docs.rs/landlock/latest/landlock/
- Landlock project — https://landlock.io/
