# crates.io release process

This document is the operator checklist for publishing x0x-symphony crates.
XSY-0035 prepares and validates the packages only; the irreversible publish is
reserved for the XSY-0036 operator go/no-go.

## Versioning policy

- `0.1.0` is the first crates.io release.
- Use SemVer for crate versions after this release.
- Schema evolution remains additive-only after the XSY-0017 schema freeze: new
  fields must be optional, existing stored fields are not renamed or retyped,
  and unknown fields are preserved so old signed claim and handoff payloads stay
  valid.

## Publish order

Publish in dependency order. `x0x-symphony-bin` is last because it is the
install target and depends on the library crates that produce the daemon and CLI
binaries.

1. `x0x-symphony-core` — leaf crate; no internal dependencies.
2. `x0x-symphony-signing` — depends on `x0x-symphony-core`.
3. `saorsa-sandbox` — depends on `x0x-symphony-core`.
4. `x0x-symphony-tracker-x0x-crdt` — depends on `x0x-symphony-core` and
   `x0x-symphony-signing`.
5. `x0x-symphony-runner-shell` — depends on `saorsa-sandbox` and
   `x0x-symphony-core`.
6. `x0x-symphony-workspace` — depends on `x0x-symphony-core`.
7. `x0x-symphony-orchestrator` — depends on `x0x-symphony-core`,
   `x0x-symphony-signing`, and `x0x-symphony-workspace`.
8. `x0x-symphony-bin` — depends on `x0x-symphony-core`,
   `x0x-symphony-signing`, `saorsa-sandbox`,
   `x0x-symphony-tracker-x0x-crdt`, `x0x-symphony-runner-shell`,
   `x0x-symphony-workspace`, and `x0x-symphony-orchestrator`; publish LAST.

The `x0x-symphony-bin` package produces two binaries:

- `x0x-symphonyd` — the daemon.
- `x0x-symphony` — the operator CLI.

## Readiness dry-runs

Before a release, run the dry-run commands in order and require each one to end
with `aborting upload due to dry run`:

```sh
cargo publish --dry-run -p x0x-symphony-core
cargo publish --dry-run -p x0x-symphony-signing
cargo publish --dry-run -p saorsa-sandbox
cargo publish --dry-run -p x0x-symphony-tracker-x0x-crdt
cargo publish --dry-run -p x0x-symphony-runner-shell
cargo publish --dry-run -p x0x-symphony-workspace
cargo publish --dry-run -p x0x-symphony-orchestrator
cargo publish --dry-run -p x0x-symphony-bin
```

For the first release only, downstream dry-runs before any upstream crate is on
crates.io need a temporary Cargo config that patches unpublished internal crate
versions back to the local checkout. Cargo strips `path` from the package it is
verifying and resolves the versioned internal dependencies through the registry;
without the patch, the dependent dry-run fails until XSY-0036 publishes the
upstream crate. Keep this config outside git and use it only for readiness
dry-runs, never for the actual publish.

The actual XSY-0036 publish must use the unpatched commands below and wait for
the crates.io index to observe each upstream crate before publishing dependents.

## Actual publish

Publishing to crates.io is irreversible: once a version is uploaded, it cannot
be unpublished; it can only be yanked. Do not run these commands until the
XSY-0036 operator go/no-go approves the release.

```sh
cargo publish -p x0x-symphony-core
cargo publish -p x0x-symphony-signing
cargo publish -p saorsa-sandbox
cargo publish -p x0x-symphony-tracker-x0x-crdt
cargo publish -p x0x-symphony-runner-shell
cargo publish -p x0x-symphony-workspace
cargo publish -p x0x-symphony-orchestrator
cargo publish -p x0x-symphony-bin
```
