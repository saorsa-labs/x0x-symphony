# x0x-symphony-runner-shell

Canonical M1 runner implementation for x0x-symphony. The crate runs a
configured child process with the rendered prompt on stdin, streams stdout and
stderr through bounded channels, and reports exit status plus elapsed duration
through the core `Runner` trait.

## Security boundary

Commands are executed with `tokio::process::Command` as an argv array. The
runner never invokes a shell implicitly and never interpolates issue fields into
`command` or `args`; issue content reaches the harness only through the rendered
prompt on stdin and through the checked-out workspace.

The child environment starts empty. Only variables declared in the resolved
runner spec or the session context are added, and secret-like names ending in
`_TOKEN`, `_KEY`, or `_SECRET` are rejected unless explicitly listed in
`allow_secret_env`.

## Built-in presets

| Preset | Command | Args | Declared env |
| --- | --- | --- | --- |
| `codex` | `codex` | `app-server` | `NO_COLOR=1`, `TERM=dumb` |
| `claude_code` | `claude` | `--print --output-format stream-json` | `NO_COLOR=1`, `TERM=dumb` |
| `kimi` | `kimi` | `--stdin` | `NO_COLOR=1`, `TERM=dumb` |
| `glm` | `glm` | `--stdin` | `NO_COLOR=1`, `TERM=dumb` |
| `minimax` | `minimax` | `--stdin` | `NO_COLOR=1`, `TERM=dumb` |
| `pi` | `pi` | `--stdin` | `NO_COLOR=1`, `TERM=dumb` |

Operators may override `command`, `args`, timeout, event-buffer sizing, or env
in `WORKFLOW.md` under `runner:` or a preset-specific block such as
`runner.claude_code:`. Overrides remain argv arrays; they are not templates.
