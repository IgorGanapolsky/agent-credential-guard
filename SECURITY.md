# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/IgorGanapolsky/agent-credential-guard/security/advisories/new)
for a way past the guard or any other security issue. Do not open a public issue, pull request or discussion with
the details until a fix ships.

Include the agent and its version (Claude Code, Codex or Cursor), the tool call that got through (tool name and
arguments), the rule you expected to fire, and the output of `bin/mac-yolo-credential-guard check -- <command>`.
Leave out live credentials and anything from a real keychain or browser profile. A command that would read a
secret is enough; the secret is not.

A bypass is in scope when a tool call that reads a credential the guard covers runs without a block, warn, log or
ask. The rule list is in [docs/CREDENTIAL-GUARD.md](./docs/CREDENTIAL-GUARD.md).

## What the guard protects, and what it does not

The guard is a pre-tool-call hook. It sees the call an agent asks to make, before it runs. It does not see what a
program does after it starts.

- **A compiled program or script that reads the keychain by itself gets past it.** `./build/tool` or
  `python3 my_script.py` runs; the guard reads the command line, not the program's code. Use it alongside a
  sandbox (Docker Sandboxes, Agent Safehouse, Claude Code's `/sandbox`), not instead of one.
- **It only guards agents whose hook settings it was installed into.** Run `bin/mac-yolo-credential-guard doctor`
  to see which agents have it. An agent started with hooks turned off, or a new agent product, is not covered.
- **If the installed hook cannot run, the agent goes ahead.** Claude Code, Codex and Cursor treat a hook that
  exits with an error (anything but a deny) as a hook problem, not a block. `doctor` reports a hook whose Node.js
  binary is gone, and `tests/test-mac-yolo-credential-guard-installed.js` checks that the installed copy runs on
  its own.
- **An agent with write access to its own settings could remove the hook.** The `guard-config` rule blocks the
  common ways to do that through a tool call. It cannot stop a person, or a program that is not an agent tool
  call, from editing the settings file.
- **macOS keychain prompts still apply.** The guard adds a check before the call. It does not replace keychain
  access control or TCC.

## Trusted inputs

Treat these as code you trust, the same as the guard itself:

- `~/.local/share/mac-yolo-safeguards/` (the installed guard and its settings file)
- the agents' hook settings (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.cursor/hooks.json`)
- any hook another tool adds next to this one

Anyone who can write to them can turn the guard off.

## Audit log

`~/Library/Logs/mac-yolo/credential-guard.jsonl` holds the rule, the ATT&CK technique, the agent, the command's
shape (program, subcommand and flag names) and whether the call ran. It holds no argument values, hosts or secrets,
so it is safe to send to a SIEM. Report it as a vulnerability if you find a log line that holds one.
