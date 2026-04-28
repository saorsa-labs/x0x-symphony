# ADR-0004 — x0x TaskList CRDT as the symphony backbone

**Status:** Accepted (2026-04-28)
**Deciders:** David Irvine
**Context:** M0 design; relates to ADR-0001

## Context

Three CRDT options exist within the Saorsa Labs ecosystem for tracking
symphony backlog state once the bootstrap JSONL adapter is retired:

**Option A — x0x's own TaskList CRDT** (`x0x/src/crdt/`)
- OR-Set checkboxes (`Empty` / `Claimed` / `Done`), LWW metadata,
  RGA ordering. MLS-encryptable. Already gossip-backed and
  partition-tolerant.
- Already wired to x0x's GUI board view (`renderSpaceBoard` in
  `x0x/src/gui/x0x-gui.html`) over `/task-lists/:id/tasks`.
- Simple model. No sub-cards, no comments, no priorities as
  first-class. Everything richer goes in the LWW metadata register.

**Option B — `communitas-kanban`** (sibling crate)
- Rich Board → Column → Card hierarchy with priority, tags, steps,
  comments, threaded discussions, state machine.
- Built on `yrs` (Yjs) CRDT, not the saorsa-gossip primitives x0x
  uses everywhere else.
- Currently coupled to communitas (project_id is a four-word
  identity, depends on communitas auth + UI service).

**Option C — extract a shared `saorsa-kanban` crate**
- Pull communitas-kanban's data model and CRDT engine into a
  standalone crate that both communitas and x0x-symphony depend on.
- Best long-term answer; significant up-front work; would gate M3.

## Decision

Adopt **Option A** for v1.0. x0x-symphony's tracker backbone is x0x's
existing TaskList CRDT, accessed through x0xd's REST API.

Symphony-specific fields (`shard`, `claim`, `handoff`, `validation`,
`priority`, `labels`, `blocked_by`) ride the existing LWW metadata
register on each TaskItem. The OR-Set checkbox states map to the
core lifecycle:

| TaskItem checkbox | Issue state          |
|-------------------|----------------------|
| `Empty`           | `todo`               |
| `Claimed`         | `in_progress`        |
| `Done`            | `done`               |

States `review`, `blocked`, `cancelled`, `duplicate` live in the LWW
metadata field `state`. Reviewers and operators read the metadata; the
GUI board renders columns by combining the checkbox and metadata.

Option B is rejected on coupling and CRDT-engine grounds: pulling `yrs`
into x0x-symphony's runtime adds a second CRDT engine alongside
saorsa-gossip's, doubling the maintenance surface for symphony's
benefit, and inheriting communitas's project-id semantics that do not
match symphony's project model.

Option C is the right destination but a wrong M3 dependency. The
architecture is designed so symphony's metadata schema is a strict
subset of communitas-kanban's Card model plus symphony extensions; if
and when `saorsa-kanban` is extracted, symphony's domain code does not
change. See `docs/design/saorsa-kanban-convergence.md` for the migration
path.

## Consequences

- M3's `x0x_crdt` adapter is a thin wrapper over existing `/task-lists`
  and `/stores` endpoints. No new CRDT engine, no new transport, no new
  GUI.
- The x0x GUI board view gains symphony-aware filters and claim badges
  in M3; the rendering chrome already exists.
- Symphony cannot offer `communitas-kanban`-style features (sub-cards,
  threaded card comments) in v1.0. If those become required, the
  upgrade path is convergence on a shared `saorsa-kanban` crate, not
  forking the data model.
- The `Issue` data model and the LWW-metadata key namespace are
  carefully designed to be a subset of `communitas-kanban`'s Card with
  symphony-only extensions, so the future merge is mechanical.
