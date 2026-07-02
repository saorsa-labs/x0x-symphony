# Operator guide

Operational guidance for running an x0x-symphony agent against a local
`issues/issues.jsonl` backlog.

> This file is seeded with the tracker lock-semantics operators must know
> (XSY-0040). The full operator + runner-authoring guide lands in XSY-0008 and
> will extend this same file. See also
> [security.md](./security.md) for the interim security posture.

## Tracker lock semantics (M1–M2 git_jsonl adapter)

The M1 `git_jsonl` tracker serializes every state transition
(claim / heartbeat / release / handoff) with a file lock. Three behaviors
matter operationally:

1. **The lock is `<git-dir>/index.lock` — the same path `git` uses.** The
   adapter takes it with an exclusive `create_new` and releases it *before*
   running `git add`/`git commit`, so git can re-acquire its own index lock.
   **Concurrent operator `git` commands** (a manual `git commit`, a second
   symphony process, etc.) contend on this single path. Under contention the
   adapter retries with backoff and, if it cannot acquire the lock within its
   budget, returns a structured `LockExhausted` error instead of corrupting
   the file. If you see `LockExhausted`, another writer is active — wait and
   retry, or serialize your manual git operations.

2. **A crashed process leaves a stale lock that must be removed by hand.** The
   adapter deletes only the lock file *it* created; it does **not** remove
   locks left behind by other (possibly crashed) processes. If a previous run
   was killed while holding `<git-dir>/index.lock`, every subsequent write
   fails with `LockExhausted` until you remove the orphaned file:

   ```sh
   rm -f .git/index.lock   # only after confirming no symphony/git process is running
   ```

   Confirm no writer is actually running before removing it — removing a lock
   that a live process still holds can corrupt the JSONL under concurrent
   writes. (Automated stale-lock recovery with a liveliness probe is tracked
   as a follow-up in XSY-0040.)

3. **Tracker commits skip git hooks (`--no-verify`).** The adapter commits
   issue-line rewrites with `git commit --no-verify`. This is deliberate: the
   tracker owns the issue backlog and must not be blocked by pre-commit or
   pre-push hooks installed in the operator's environment. Any policy you want
   to enforce via hooks must be applied out-of-band (e.g. a CI check on the
   tracker commit, or a separate review step).

For the full concurrency model, retry/backoff tuning, and the M3 supersession
path (this adapter is deleted by XSY-0024 when the `x0x_crdt` tracker becomes
the permanent backend), see the crate-level documentation of
`x0x-symphony-tracker-git-jsonl`.
