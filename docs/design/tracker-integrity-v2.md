# Tracker Integrity v2 — Fold Specification (design r2)

Status: WP-0 + WP-A implemented (`crates/x0x-symphony-tracker-x0x-crdt/src/v2/`).
Tracks x0x-symphony issue #10. Incorporates the Codex design review of r1
(verdict: UNSOUND as specified; findings C1–C8, all resolved below).
Companion x0x work: WP-X `AccessPolicy::AppendOnly` (x0x v0.33.0, branch
`feat/kv-append-only-policy`).

This document is the **normative spec** for the pure fold implemented by
`v2::fold::fold_v2`. The implementation must not deviate from it; deviations
are bugs in one or the other and must be reconciled loudly.

## 1. Model

A v2 task list is a set of **per-author, append-only event stores**:

- Topic: `symphony2-ev-<list-uuid>-<author-agent-id>` — one store per author
  (C4: unique topic per store keeps x0xd's topic-keyed REST surface as-is).
- Store policy: x0x `AccessPolicy::AppendOnly` (C1) — existing keys are
  immutable in local ops **and** `merge_delta`; the keyset is add-only.
  - REST: created with `POST /stores {"policy": "append_only"}`; PUT to an
    existing key → 409; DELETE → 409.
  - Interim gate: until x0x ≥ 0.33.0 is the deployed baseline, the
    `v2_store_policy = "signed"` config falls back to mutable `signed`
    stores (`StorePolicyMode::SignedFallback`, loud TODO in
    `v2/store.rs`). In that mode the C1 deletion residual is NOT closed.
    The default mode requires `append_only` and **fails loudly**
    (`V2StoreError::PolicyNotHonored`) when the daemon ignores the flag —
    older daemons silently drop unknown JSON fields, so the create response's
    `policy` field is re-checked; silence is not acceptance.
- Readers join peer stores via `POST /stores/<topic>/join
  {"expected_owner": <author-id>}` and read keys. Store ids are never
  computed client-side; topics are the addressing.
- List reference: `symphony2:<list-uuid>:<creator-agent-id>`
  (`V2ListRef`). The `symphony2:` prefix is a disjoint namespace: old
  daemons do not recognize it, and v1 lists never resolve into it.

Records inside an author's store:

| Key | Content | Signed context |
|---|---|---|
| `card-self` | raw ML-DSA-65 public key bytes (first key written) | — (self-certifying by hash) |
| `genesis` (creator only) | `GenesisManifestV2` envelope | `x0x-symphony-genesis-v2` |
| `roster-<epoch:010>-<hash>` (creator only) | `RosterEventV2` envelope | `x0x-symphony-roster-v2` |
| `ev-<issue-id>-<event-hash>` | `TransitionEventV2` envelope | `x0x-symphony-transition-v2` |

Approval records (`x0x-symphony-approval-v2`) become their own per-key
records in WP-B; in WP-A they appear embedded inside requeue justifications.

Heartbeats are v1-style **mutable** liveness keys (`hb-<issue-id>`) and are
**never fold inputs**. Because the event store is append-only they cannot
live there; they live in a mutable companion store
`symphony2-hb-<list-uuid>-<author-agent-id>` (policy `signed`). This is the
one deliberate refinement over the r2 sketch ("hb-<issue> in own store"),
forced by C1's append-only resolution; semantics are unchanged
(non-authoritative, never affect folded state).

### 1.1 Envelope and hashing

Every signed record is stored as an `EventEnvelope` JSON document carrying
the **exact signed payload bytes** (`payload_b64`), the detached ML-DSA-65
signature, the signing public key, and the claimed signer id. Readers parse
payloads from those exact bytes, so there is no canonical-serialization
ambiguity. Definitions:

- `event_hash = SHA-256(payload bytes)`, lowercase hex. The same value is
  embedded in the record's key (`ev-<issue>-<hash>`): records are
  content-addressed, and a key/content mismatch is inadmissible.
- Signatures cover x0x's external DST
  `[0xF0] || "x0x.external-agent-sign.v1" || len(context):u32BE || context || payload`
  — byte-identical to `/agent/sign` (x0x issue #133). Signing goes through
  the daemon; verification is **local and pure**
  (`v2::identity::verify_external_signature`, saorsa-pqc), which is what
  lets the fold be a pure function.
- `derive_agent_id(pk) = SHA-256("AUTONOMI_PEER_ID_V2:" || pk)`, hex —
  identical to ant-quic's peer-id derivation. Agent ids ARE key hashes;
  author resolution is therefore self-certifying (C5): no TOFU.

### 1.2 Signed-payload bindings (C8)

Every `TransitionEventV2` payload binds: `schema (=2)`, `list_uuid`,
`genesis_manifest_hash`, `roster_epoch`, `issue_id`, the kind and its claim
bindings (`claim_nonce`, plus `claimed_event_hash` for post-claim
transitions), `actor`, `lamport`, `author_seq`, `prev_own_event_hash`.
An event is admissible only in the exact list+genesis+epoch it names; a
byte-identical replay anywhere else fails admission.

## 2. The fold

```
fold_v2 : FoldInput -> Result<FoldOutput, ListRefusal>
```

`FoldInput = { list_uuid, creator, streams: [AuthorStream] }` where
`AuthorStream = { owner, card_self?, records: [(key, value bytes)] }` is the
verbatim content of one author's store as anchored by the local x0xd.

**Purity contract**: no I/O, no clocks, no trust lookups, no randomness.
Trust (`required_trust` vs local contacts) and approval TTL are dispatch-time
local policy ONLY (C2/C3): they may refuse to dispatch or display, they never
change folded state. Two independent folds of the same event set agree; input
order (streams and records) is canonicalized away.

### 2.1 Genesis resolution — the refusal gate (downgrade defense, Q5)

1. The creator's stream must be present, its `card-self` must derive to the
   creator id, and `genesis` must exist.
2. The genesis envelope must verify under `x0x-symphony-genesis-v2`, be
   signed with the creator's card-self key by the creator id, and its payload
   must name `schema=2`, `kind="genesis"`, the addressed `list_uuid`, the
   addressed `creator`, and a non-empty roster.
3. **Any failure ⇒ the entire list is refused** (`ListRefusal`). No partial
   state, no v1 fallback, ever. A v2-prefixed list reference that fails to
   parse is likewise refused upstream.

`genesis_manifest_hash = SHA-256(genesis payload bytes)` anchors everything.

### 2.2 Roster chain

- Epoch 0 = the genesis roster.
- `RosterEventV2` records (creator's store only; creator-signed only in
  v0.2.0) each bind `list_uuid`, `genesis_manifest_hash`, `roster_epoch ≥ 1`,
  `prev_roster_hash`, the complete new roster, `actor = creator`.
- The chain is walked from epoch 1: exactly one verified event whose
  `prev_roster_hash` equals the previous accepted hash (genesis hash for
  epoch 1) extends the chain. Zero candidates end the chain; two or more
  distinct linked candidates are a **creator roster fork**: fork evidence is
  surfaced and the chain ends *before* the forked epoch (self-harm only).
- Events naming an epoch beyond the verified chain are inadmissible
  ("unknown roster epoch").

Membership rule: an event is admissible only if its `actor` is in the roster
**at the event's named epoch**. (Residual, documented: a member removed at
epoch N+1 can still author events naming epoch ≤ N — retroactive fencing of
departed members is a dispatch-time trust decision, not a fold decision.
WP-B's consume fencing narrows the practical impact.)

### 2.3 Phase 1 — admission (per event)

An `ev-*` record is admissible iff ALL of:

1. **Envelope**: schema 2, algorithm `x0x.agent-sign.v2.ml-dsa-65`, context
   `x0x-symphony-transition-v2`, valid base64, non-empty payload, ML-DSA-65
   signature verifies over the external DST.
2. **Four-way author binding (C5)**:
   `derive_agent_id(envelope.public_key) == envelope.signer_agent_id ==
   stream.owner == payload.actor`, and `envelope.public_key ==` the stream's
   verified `card-self` key.
3. **C8 bindings**: payload `schema == 2`, `list_uuid` and
   `genesis_manifest_hash` match this list's.
4. **Content address**: record key == `ev-<payload.issue_id>-<event_hash>`.
5. **Roster**: `actor` ∈ roster at `roster_epoch` (§2.2).
6. **Requeue justification (C6)**, when kind = `requeue`:
   - the embedded approval envelope verifies under
     `x0x-symphony-approval-v2` with its own self-certifying signer binding;
   - `SHA-256(approval payload) == justification.approval_event_hash ==
     justification.approval_payload_sha256` (in v2 the event hash IS the
     payload hash; both fields are kept for WP-B evolution);
   - approval payload binds `schema=2`, `kind="approval"`, this
     `list_uuid` + `genesis_manifest_hash`, the requeue's `issue_id`,
     `block_event_hash == justification.block_event_hash`,
     `claim_nonce == justification.claim_nonce`,
     `approver == justification.approver == approval signer`;
   - the approver is a roster member at the requeue's named epoch.
7. **Per-author hash chain (C7)**: for each author, `author_seq` must run
   strictly 1, 2, 3, … and `prev_own_event_hash` must equal the previous
   event's hash (the genesis manifest hash anchors seq 1). Admission is
   **prefix-only**: the first gap, link break, or fork makes that author's
   remaining events inadmissible. A fork (two signature-valid events with the
   same seq) additionally surfaces `ForkEvidence {author, seq, hashes}` —
   two signed events with one seq are self-authenticating proof of
   equivocation.
8. **Lamport cap (C7)**: candidates surviving 1–7 are walked in ascending
   `(lamport, author, event_hash)` order with `running_max` starting at 0;
   an event is admitted iff `lamport ≤ running_max + 64`, and admission
   raises `running_max`. A lamport-rejected event also truncates its
   author's chain from that seq (prefix-only admission is preserved). The
   rule is a function of the candidate multiset only ⇒ order-independent.
   Withheld-event semantics are unchanged from r2: a withheld event can
   re-order a winner only within the documented partition window; chains
   make silent rewriting of one's own history detectable.

Every rejection is surfaced in `FoldOutput.rejections` (phase, author, key,
reason) — hostile input is visible, never silently dropped. Rejections and
fork evidence are canonically sorted so diagnostics are order-independent
too.

### 2.4 Phase 2 — state machine

Admitted events are applied in ascending `(lamport, author, event_hash)`
order — a total order, so concurrent claims resolve identically everywhere.

Per issue:

| Kind | Precondition | Effect |
|---|---|---|
| `open` | issue does not exist | create, status **Open** |
| `claim` | status Open | **Claimed**{actor, nonce, claim event hash} |
| `release` | fence(actor, nonce, claim hash) | **Open** |
| `block` | fence(actor, nonce, claim hash) | **Blocked**{…, block hash, reason} |
| `complete` | fence(actor, nonce, claim hash) | **Done** (terminal) |
| `requeue` | status Blocked **with reason `awaiting_approval`**, justification names the *current* block hash and parked nonce | **Open** |

`fence(actor, nonce, hash)`: status is Claimed AND `actor == claimant` AND
`nonce == claim_nonce` AND `hash == claim_event_hash`. A losing claimant's
release/block/complete is therefore ineffective — it cannot touch the
winner's claim.

**No block reason other than `awaiting_approval` is ever requeue-able, by
any author** (C6). Admin repair of a stuck issue = a new issue, not
mutation.

Ineffective events are recorded as phase-2 rejections and change nothing.
`FoldOutput` exposes per-issue `applied` event-hash logs, `max_admitted_lamport`
(callers stamp their next event with `max+1`), rejections, and fork evidence.

## 3. What is deliberately NOT in the fold

- **Trust** (C2): canonical membership is the signed roster; local trust may
  refuse dispatch/display only.
- **TTL** (C3): approval expiry is checked at the dispatch gate against the
  local clock; folded state never depends on clocks.
- **Consumption** (WP-B): per-key `ApprovalEvent`/`ConsumeEvent`,
  claim-fenced consume + settle re-read, and duplicate/lost-consume
  diagnostics land in WP-B on top of this fold.
- **Compaction**: none in v0.2.0; future compaction must Merkle-commit
  history.
- **Shard-primary consume** (Q6): recorded as a future liveness knob; not in
  v0.2.0.

## 4. Residual windows (honest accounting, unchanged from r2)

- Live-partition double-execution: narrowed, deterministic and detectable
  after heal; runners must stay idempotent (fully addressed only by WP-B
  fencing + the documented partition window).
- Withheld events: an author can withhold its own suffix; chains make later
  publication detectable, and lamport capping bounds future-dating.
- Epoch-pinned membership: removed members can author into old epochs until
  dispatch-time policy or WP-B fencing intervenes (§2.2).
- `SignedFallback` mode: mutable stores — C1 deletion residual open. Interim
  only; see the WP-X gate in `v2/store.rs`.

## 5. Test map

`crates/x0x-symphony-tracker-x0x-crdt/tests/v2_fold.rs` exercises every rule
above with real ML-DSA-65-signed events: per-binding admission rejections
(wrong signer key, wrong store, actor mismatch, missing/mismatched
card-self, non-roster author, unknown epoch), chain gap/fork (+evidence),
lamport boundary (+64 accepted, beyond rejected), cross-list and
cross-genesis byte-identical replay, wrong-key content addressing, C6
requeue violations one element at a time, deterministic concurrent-claim
winners under both orders, stale-claimant fencing, full happy path, release/
reclaim, 10-seed shuffle determinism, and genesis refusals. Identity vectors
in `src/v2/identity.rs` are computed independently of the implementation;
`tests/v2_live_x0xd.rs` cross-checks a live `/agent/sign` response against
the local verifier when `X0XD_URL` is set.
