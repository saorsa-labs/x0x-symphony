# Future work — convergence with `saorsa-kanban`

**Status:** Future-work note. Not blocking any current milestone.

## Background

Two kanban-shaped systems live in the Saorsa Labs codebase today:

- **x0x TaskList CRDT** — simple list-of-tasks with OR-Set checkboxes
  and LWW metadata. Owned by x0x. Used by the x0x GUI board view and
  (per ADR-0004) the v1.0 symphony backbone.
- **`communitas-kanban`** — rich Board → Column → Card model with
  priority, tags, steps, comments, threaded discussions. Owned by
  communitas. Built on `yrs` (Yjs).

These are independent today. ADR-0004 keeps them independent for v1.0
to avoid blocking symphony on a refactor.

## Convergence target

Extract a standalone `saorsa-labs/saorsa-kanban` crate that:

1. Defines the Board / Column / Card / Step / Comment data model used
   by communitas-kanban today.
2. Picks a single CRDT engine. Either keep `yrs` and migrate x0x's
   TaskList to it, or port communitas-kanban onto saorsa-gossip
   primitives. The latter is more consistent with the rest of the
   stack but a larger lift.
3. Exposes a stable Rust API that both communitas and x0x depend on.
4. Is exposed through x0xd's REST API alongside (or replacing) the
   existing `/task-lists` endpoints.

## Symphony's role

Symphony's metadata schema is intentionally a strict subset of
`communitas-kanban`'s Card model plus symphony-specific extensions
(`shard`, `claim`, `handoff`, `validation`, `proofs_link`). When the
shared crate exists, symphony's domain code does not change; only the
Tracker adapter swaps from `x0x_crdt` (TaskList-backed) to
`saorsa_kanban` (shared-crate-backed).

Symphony's `Issue` struct is the unit of integration:

| Symphony `Issue` field    | x0x TaskList                    | `communitas-kanban` Card        |
|---------------------------|---------------------------------|---------------------------------|
| `id`                      | TaskItem id                     | Card id                         |
| `title`                   | TaskItem text                   | Card title                      |
| `description`             | LWW `description`               | Card description                |
| `state` (lifecycle)       | checkbox + LWW `state`          | Card column + state machine     |
| `priority`                | LWW `priority`                  | Card priority                   |
| `labels`                  | LWW `labels`                    | Card tags                       |
| `blocked_by`              | LWW `blocked_by`                | (extension via tags or links)   |
| `shard` / `claim`         | LWW symphony extension          | LWW symphony extension          |
| `handoff`                 | LWW symphony extension          | LWW symphony extension          |

If `communitas-kanban` becomes the shared model, symphony's extensions
remain extensions on the Card.

## Triggers

Reasons to start convergence work:

1. Symphony users repeatedly ask for `communitas-kanban`-style features
   (sub-cards, threaded comments, richer column workflow) and the
   demand justifies the engine consolidation.
2. communitas needs symphony-style claim/handoff semantics on its own
   boards.
3. Maintenance cost of running two CRDT engines (saorsa-gossip TaskList
   + `yrs`) becomes painful in practice.

## Non-triggers

- Aesthetic dislike of two kanban systems coexisting. They are not
  duplicates; they serve different audiences and run on different
  CRDT engines for sound reasons.
- Symphony alone wanting richer features. Symphony can extend its own
  metadata register without moving to `yrs`.
