# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Built-in `pi`, `claude_code`, and `codex` presets now match the real CLI
  contracts** (#7). Verified live against the pinned harness versions
  Claude Code 2.1.208, pi 0.80.3, and codex-cli 0.144.1:
  - `pi`: `--stdin` → `--print` (pi 0.80.3 rejects `--stdin`; `--print` runs
    non-interactively and reads the prompt from stdin).
  - `claude_code`: added mandatory `--verbose` (Claude Code refuses
    `--print --output-format stream-json` without it).
  - `codex`: `app-server` → `exec` (`app-server` speaks JSON-RPC and cannot
    consume the rendered stdin prompt; `exec` reads it directly).
  Other harness versions remain supported via the `runner.command`/`runner.args`
  and per-preset `runner.<preset>.args` overrides in `WORKFLOW.md`.

### Added

- Live preset contract smoke tests
  (`crates/x0x-symphony-runner-shell/tests/preset_live_smoke.rs`) and a
  `just preset-smoke` recipe: spawn each installed harness with the preset
  argv, feed a trivial stdin prompt, and fail only on argv/usage rejection.
  Gated behind `X0X_SYMPHONY_PRESET_SMOKE=1`; skipped when a harness binary is
  absent. Pinned preset/harness versions documented in
  `docs/symphony/runner-authoring.md`.

## [v0.1.2] — 2026-07-15

Patch release: makes locally-created issues actually dispatch, plus operator
UX fixes. Found and fixed during the 2026-07-14 x0x SKILL.md testnet sweep.

### Fixed

- **Locally-created issues now dispatch instead of blocking forever.** Under
  `signing.policy: required`, every issue read back from the CRDT is stamped
  `network_sourced` (fail-closed), and the dispatch gate refused any such issue
  without verified ML-DSA-65 provenance — but `create_issue` never signed local
  issues, so `x0x-symphony issue new …` produced a task that went straight to
  `[blocked]` and never released. The tracker now signs a deterministic
  `{issue_id, title, description}` payload via x0xd `/agent/sign` and persists a
  provenance blob in the companion store; the read path verifies it and attaches
  `SignatureProvenance::Verified`. The gate additionally treats `signer == self`
  as implicitly trusted (a daemon is never in its own x0xd contacts). Unsigned or
  untrusted non-self signers are still refused. Verified end-to-end against a
  clean x0xd v0.31.3: `issue new` → `in_progress` → `review` in ~8 s.

- **Daemon auto-creates its tracker surfaces on startup.** A fresh `x0x-symphonyd`
  against a clean x0xd died with `orphan workspace sweep failed … task list not
  found`, and `issue new` returned 500 `store not found` while leaving a bare
  zombie task. Startup now ensures both the `TaskList` and the companion
  `symphony-<list_id>` `KvStore` exist (idempotent, group-scope aware), and a
  failed sidecar write during issue creation marks the task terminal instead of
  leaving a zombie.

- **Rate-limited malformed worker-gossip log spam.** On a shared gossip plane,
  foreign/older agents' worker cards produced a steady stream of WARN decode
  failures. Repeats within a 5-minute window per discriminator now drop to DEBUG;
  genuinely unexpected failures still WARN on first hit.

### Changed

- `docs/symphony/operator.md`: documented the `X0X_API_TOKEN` bearer env, the
  startup surface-creation step, and the dispatch/provenance interaction.

## [v0.1.1] — 2026-07-07

Patch release: security fix and the first release with post-quantum archive
signing.

### Added

- First release with working ML-DSA-65 archive signing in `release.yml`
  (XSY-0058): the `sign-release` job is restored and the org
  `ML_DSA_SECRET_KEY` encoding is corrected (verified green by the dispatch-only
  `verify-signing-secret` workflow), so published artifacts now ship `.sig`
  files alongside GPG/codesign/SHA-256. v0.1.0 shipped without these.

### Security

- Constant-time bearer-token comparison in the daemon API (fixes #5):
  `bearer_header_matches` and `query_token_matches` now hash both sides with
  SHA-256 and compare via `subtle::ConstantTimeEq` (`core::constant_time_eq`),
  mirroring x0x's server auth. Closes a timing side-channel (LOW; loopback-only,
  32-byte hex token).

### Changed

- ADR-0006 Amendment 1 records the XSY-0057 decision: native macOS Seatbelt is
  deferred indefinitely; macOS containment stays Tier-1 `sandbox-exec` (the
  industry-standard MACF path). `docs/symphony/security.md` reframed
  accordingly.

## [v0.1.0] — 2026-07-02

First public release. Distributed task orchestration for AI agents: sharded
claim ownership, post-quantum (ML-DSA-65) signed claims/handoffs, a
consent-gated dispatch gate for network-sourced work, and a native Linux
Landlock + cgroup-v2 sandbox (`#![forbid(unsafe_code)]`). Built on the x0x
TaskList CRDT backbone and ant-quic transport.

M4/M5 distributed operations, consent, sandboxing, and polish.

### Added

- M4 worker discovery (XSY-0025): signed `WorkerCard` publication on the
  x0x/symphony workers topic, TTL refresh, verified live worker view, and
  `/symphony/workers` / `x0x-symphony workers` observability.
- M4 live shard assignment (XSY-0026): daemon-backed issue creation now assigns
  shard records from the live `WorkerView` snapshot and records the view epoch.
- M4 consent-gated network dispatch (XSY-0048..XSY-0056): `off` / `approve` /
  `auto` policy enum, signed approval and denial records, single-use approval
  consumption, REST approval API, CLI approval commands, SSE approval events,
  and GUI PendingApproval follow-up in x0x.
- M4/M5 observability polish (XSY-0032, XSY-0053): single-task detail endpoint,
  route catalog, granular proof artefact routes, approval events on SSE, and
  CLI mirrors for status, workers, tasks, approvals, proofs, and routes.
- M5 proof retention (XSY-0033): configurable `retention.proofs_days` and
  `retention.reap_interval_secs` with a race-safe proof artefact reaper.
- M4 partition-reunion validation harness (XSY-0029): ignored multi-daemon
  stress harness and operator documentation for ADR-0002 verification.
- M4 native Linux sandbox backend (XSY-0042): internal
  `saorsa-sandbox-launcher`, Landlock access control, cgroup-v2 resource
  bounding, and `saorsa-sandbox` extraction with `#![forbid(unsafe_code)]`.
- M5 documentation polish (XSY-0034): README quickstart, expanded changelog,
  and an operator-guide worked example.

### Changed

- ⚠️ BREAKING (XSY-0042): sandbox support moved into the `saorsa-sandbox`
  crate; backend APIs now use the D1/D2 split (`prepare` → `prepare` / `wrap` /
  `child_started`) and `WrappedCommand.env_additions` instead of a complete
  replacement `env` map.
- ⚠️ BREAKING (XSY-0045): required-signing reads now strip only invalid,
  unsigned, or mismatched claims and keep the issue visible (normalizing
  claim-only `in_progress` items back to `todo`) instead of dropping the whole
  issue from candidate/detail reads.
- M4 `security.network_dispatch` now fails closed on unknown values; legacy
  boolean values map only to `off` / `approve` with warnings, never to `auto`.
- M4 worker shard creation no longer treats static `sharding.workers` as the
  source of truth; it is retained only for historical tests and records.
- M5 operator docs now describe x0xd-backed issue creation; the old local JSONL
  writer is no longer the runtime path.

### Removed

- ⚠️ BREAKING (XSY-0031): the legacy top-level `codex:` `WORKFLOW.md` block is
  no longer accepted. Config load and `config check` fail with a structured
  error; use `runner: {kind: shell, preset: codex}` instead.

### Security

- M4 consent gate (XSY-0048..XSY-0056): network-sourced tasks can run only under
  `auto` or after a valid, unexpired, payload-bound, cryptographically verified
  approval; missing approval, expired approval, verifier transport errors, or a
  missing verifier fail closed.
- M4 approval hardening (XSY-0055, XSY-0056): the dispatch gate verifies
  approval signatures via ML-DSA-65 and refuses `approve`-policy dispatch when
  no signing client or trusted-key resolver is configured.
- M4 native Linux sandbox (XSY-0042): network-sourced work fails closed when an
  enforcing sandbox backend is unavailable; local work may degrade only with a
  loud warning according to `on_unavailable`.
- M4 forged approval events are ignored with warn-level audit logging.

### Fixed

- XSY-0045 surfaces bad-claim verification notices while preserving issue
  visibility, preventing one forged claim from hiding a valid task.
- XSY-0046 added cross-version schema/signature survival coverage so absent
  additive fields do not invalidate v1 claim or handoff signatures.
- XSY-0032 closed observability gaps for detail views, proof routes, worker
  state, and route enumeration.
- XSY-0033 prevents proof cleanup from racing with active `in_progress` runs.

## [v0.0.M3] — x0x CRDT tracker and network dispatch gate (2026-07-03)

### Added

- M3 x0x CRDT tracker (XSY-0019): `x0x_crdt` adapter backed by x0xd TaskList
  REST endpoints plus a deterministic `symphony-<list-id>` KvStore sidecar.
- MLS/group-scoped task-list dispatch (XSY-0021): optional `tracker.group`
  resolves or joins x0xd named/MLS groups and scopes the configured TaskList.
- x0x GUI board follow-up (XSY-0023): symphony filters, state grouping, shard
  role, claim freshness, priority, and validation badges in the x0x board view.
- Live x0xd sign/verify contract coverage (XSY-0044) for ML-DSA-65 claim and
  handoff payload bytes.

### Changed

- ⚠️ BREAKING (XSY-0024): signing moved out of tracker adapters into the
  dedicated `x0x-symphony-signing` crate. Downstream imports of adapter-local
  signing helpers must move to the new crate.
- The daemon now resolves its runtime agent identity from x0xd `/agent` and
  uses x0xd as the tracker/signing base URL.

### Removed

- ⚠️ BREAKING (XSY-0019, XSY-0024): the M1/M2 git JSONL runtime tracker was
  deleted. `x0x_crdt` is the only runtime tracker; `issues/issues.jsonl`
  remains only this repository's historical issue database for human handoffs.

### Security

- M3 dispatch gate (XSY-0039, hardened at `6c02ae1`): the orchestrator refuses
  network-sourced issues unless ML-DSA-65 signature provenance verifies and the
  signer meets the configured x0xd trust threshold.
- Trust-gated dispatch (XSY-0022): x0xd `/contacts` trust levels feed the
  execute-path gate, with blocked or insufficient-trust signers refused.
- Signature verification availability hardening (XSY-0043): verify transport
  failures surface as errors/degraded state instead of being treated as invalid
  signatures or empty queues.

### Fixed

- XSY-0043 separated verify-transport-failure from signature-invalid and added
  bounded verification caching.
- M3 hard-gate follow-up made the dispatch gate self-enforcing against
  delegation gaps before any workspace, hook, or runner side effect.

## [v0.0.M2] — claim primitives, artefacts, signing, and sandbox profiles (2026-07-03)

### Added

- Shard assignment at issue creation (XSY-0013) and heartbeat / TTL takeover
  with mocked-clock tests (XSY-0014).
- Validation artefact sink (XSY-0015): per-run `proofs/<issue>/<timestamp>/`
  directories, stdout/stderr capture, and manifest metadata.
- Handoff writer enrichment (XSY-0016): `proofs_dir`, validation summaries, and
  git-diff-derived `files_changed` in handoff records.
- Schema freeze v1 (XSY-0017): documented shard, claim, handoff, and additive
  evolution rules in `issues/schema.md`.
- Startup reconcile support for abandon-record proofs and orphan workspaces
  (XSY-0018, XSY-0037).
- Lifecycle hook execution in dispatch (XSY-0041): `after_create`, `before_run`,
  `after_run`, and `before_remove` with explicit hook environment.
- Sandbox profiles Tier 1 (XSY-0027): `CommandPlan`, `WrappedCommand`, and
  Bubblewrap / Landlock wrapper / `sandbox-exec` backend selection.

### Changed

- M2 execution hardened the orchestrator handoff path so validation artefacts
  and files-changed summaries travel with review-state handoffs.
- Workspace and hook behavior was tightened around process groups, budgets,
  allow-lists, and deterministic path containment.

### Security

- ML-DSA-65 signing and verification for claim and handoff payloads landed in
  M2 (XSY-0020), including domain-separated context strings and x0xd-backed
  `/agent/sign` / `/agent/verify` integration.
- Sandbox profiles (XSY-0027) added a host-enforcement layer for configured
  shell runners while preserving explicit unsandboxed local-development mode.
- Red-team LOW fixes (XSY-0047): owner-only workspace directory permissions,
  control-character rejection in hook env values, env key boundary tests, and
  PATH/Path case-sensitivity coverage.

### Fixed

- Windows compile checks were restored for the workspace crate path.
- Startup reconciliation now renders abandoned work into proofs and completes
  stale-claim cleanup.
- Workspace hardening follow-ups fixed heartbeat, budget, allow-list, adapter,
  containment, and orphan-sweep gaps found during M1/M2 review.

## [v0.0.M1] — M0 bootstrap and local runner vertical slice (2026-07-02)

### Added

- M0 repository bootstrap (XSY-0001): architecture source of truth, ADR set,
  initial roadmap, issue database, license, and contribution scaffolding.
- Core abstractions (XSY-0002): `Tracker`, `Runner`, `Workspace`, issue domain
  types, claims, handoffs, and shared error shapes.
- M1 bootstrap tracker (XSY-0003): git-committed JSONL tracker for the local
  vertical slice (explicitly throwaway and later removed at M3).
- Shell runner (XSY-0004): static argv execution, issue prompt over stdin,
  Codex and Claude Code presets, bounded output, and process-group timeouts.
- Workspace manager (XSY-0005): per-issue workspace creation, ID sanitization,
  root containment, and hook scaffolding.
- Orchestrator (XSY-0006): poll loop, claim, dispatch, concurrency limits,
  retries, heartbeat/budget guard follow-ups, release, and review handoff.
- Daemon and CLI binaries (XSY-0007): `x0x-symphonyd`, `x0x-symphony`, loopback
  HTTP API, bearer-token auth, tasks/claim/handoff/status/proofs/config/routes
  operator commands.
- Operator and runner-authoring guides plus M1 proof transcripts (XSY-0008).
- CI/tooling (XSY-0009..XSY-0012): workspace validation workflow, just recipes,
  release workflow stub, and daily cargo-audit security workflow.

### Changed

- M1 hardening follow-ups tightened workspace containment, hook execution,
  heartbeat handling, retry budgets, and adapter tests before the M1 tag.

### Security

- Interim security posture documented local-operator-only execution, empty
  runner/hook environments plus explicit allow-lists, secret deny-lists, and
  WORKFLOW.md as the operator-vouched command source.
- Workspace path containment and process-group cleanup established the first
  execution safety boundary before sandbox profiles existed.

### Fixed

- Enabled Tokio `fs` features in dev dependencies for workspace tests.
- Closed M1 audit findings around containment, heartbeat, budget guards, and
  allow-list handling before release tagging.
