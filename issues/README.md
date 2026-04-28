# x0x-symphony Issue Database

This directory is the git-committed issue tracker for x0x-symphony, mirroring
the bootstrap pattern used by `x0x/issues/`.

`issues.jsonl` contains one UTF-8 JSON object per line. The file is
intentionally line-oriented so agents and humans can update individual
records with small diffs.

## Lifespan

This JSONL database is the **bootstrap tracker** used through M1 and M2.
At M3, x0x-symphony switches to the `x0x_crdt` adapter that reads/writes
x0x's TaskList CRDT through x0xd's REST API. At that point, this directory
is removed (see ADR-0001 and ADR-0003).

Until then, `issues.jsonl` is the authoritative backlog for x0x-symphony's
own development. Issue prefix is `XSY-`.

## Files

- `issues.jsonl` — canonical active issue database.
- `schema.md` — record schema, states, and update rules.
