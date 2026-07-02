# §2 M1 demo transcript

Reproduces the plan §2 definition-of-done demo against the real
`x0x-symphonyd` daemon and `x0x-symphony` CLI, using a stub shell runner
(reads the prompt from stdin, exits 0 — see runner-authoring.md).
All commands run against a throwaway git repo with a correctly-initialized
0-byte `issues/issues.jsonl`.

## Setup

```sh
$ git init; : > issues/issues.jsonl; git commit -qm seed   # empty backlog
$ cat WORKFLOW.md  # runner.command points at a stub script that exits 0
```

## config check

```
$ x0x-symphony config check --config WORKFLOW.md
config ok
exit=0
```

## seed a todo issue, start the daemon

```
$ git commit -m 'seed: XSY-9001 todo'   # backlog now has one todo issue
$ x0x-symphonyd --config WORKFLOW.md --data-dir <tmp>/data --bind 127.0.0.1:0 &
daemon pid=62704
bound port: 63179
```

## auth: 401 without token, 200 with token

```
$ curl -s -o /dev/null -w '%{http_code}' .../symphony/status   # no token
401
$ curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer <token>' .../symphony/status
200
```

## tasks (CLI) before / during dispatch

```
$ x0x-symphony tasks
tasks:
- XSY-9001 [review] p2 demo issue
```

## tasks --state review (issue reached review)

```
$ x0x-symphony tasks --state review
tasks:
- XSY-9001 [review] p2 demo issue
```

## git log (claim + handoff commits)

```
$ git log --oneline issues/issues.jsonl
650ca12 x0x-symphony: handoff XSY-9001
4192667 x0x-symphony: claim XSY-9001
aa017c2 seed: XSY-9001 todo
2de436c seed: empty backlog
```

## final issue state

```
state: review | handoff: True
```
