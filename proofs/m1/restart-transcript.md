# §5 restart / resume-or-release transcript (M1 gate)

Proves the §5 resilience requirement: killing the daemon mid-run and
restarting it resumes-or-releases the claim without losing or corrupting
state. The runner hangs on first invocation (no `GO` marker) so the run is
in flight when the daemon is stopped; the marker is touched before restart
so the re-acquired run completes.

## 1. start daemon → issue claimed, run in flight

```sh
$ x0x-symphonyd --config WORKFLOW.md --data-dir <tmp>/data --bind 127.0.0.1:0 &
# daemon pid=70025, port read from <tmp>/data/daemon.port
$ x0x-symphony status   # mid-run: one in_progress claim
status:
agent: symphonyd
orchestrator_attached: true
counts:
- in_progress: 1
active_claims:
- XSY-9002 [in_progress] by symphonyd heartbeat 2026-07-02T18:13:26.290399000Z
```

## 2. SIGTERM → graceful shutdown releases the claim

```sh
$ kill -TERM 70025   # graceful: run releases claim with 'shutdown', workspace preserved
# daemon exited
$ git log --oneline
c9da538 x0x-symphony: release XSY-9002
93a0d1f x0x-symphony: claim XSY-9002
b467426 seed: XSY-9002 todo
68ce487 seed
# issue state after graceful shutdown:
#   state: todo | claim: None
```

## 3. touch the GO marker, restart the daemon

```sh
$ find $WSROOT -mindepth 1 -maxdepth 1 -type d -exec touch {}/GO \;   # runner will succeed this time
$ x0x-symphonyd --config WORKFLOW.md --data-dir <tmp>/data --bind 127.0.0.1:0 &
# restarted daemon pid=70343, new port read fresh from <tmp>/data/daemon.port
```

## 4. issue completed on restart (re-claimed, handed off to review)

```sh
$ x0x-symphony tasks --state review
tasks:
- XSY-9002 [review] p2 restart demo
$ git log --oneline   # full history: seed → claim → release(shutdown) → claim → handoff
63d336f x0x-symphony: handoff XSY-9002
5d2ebb1 x0x-symphony: claim XSY-9002
c9da538 x0x-symphony: release XSY-9002
93a0d1f x0x-symphony: claim XSY-9002
b467426 seed: XSY-9002 todo
68ce487 seed
# final issue state:
#   state: review | handoff: True
```

## hard-kill (SIGKILL) stale-claim release

The SIGTERM path above is the M1 graceful-shutdown proof. The hard-kill path
(a crashed daemon leaves a claim whose heartbeat ages past `claim_ttl`) is
covered deterministically by the orchestrator unit test
`reconcile_releases_stale_and_keeps_fresh_self_claims`, which uses an
injected `ManualClock` to age a self-owned claim past the TTL and asserts it
is released with `expired_heartbeat` on the next `reconcile()`, while a
fresh self-claim is resumed and a foreign claim is left untouched. (A live
hard-kill demo would require waiting the full `claim_ttl`; the unit test is
the deterministic equivalent and is part of the `just check` run in
`containment-transcript.md`.)
