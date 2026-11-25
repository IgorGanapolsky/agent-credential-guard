# Agent credential guard

Coding agents run with approvals off will run any command they decide they need. On a Mac, that includes
reading the keychain:

```sh
security find-generic-password -s "Chrome Safe Storage" -w
```

That one line prints the key that decrypts every saved Chrome password and cookie. No prompt appears, because
prompts are off.

This guard is a pre-tool-call hook for **Claude Code, Codex and Cursor**. It reads each command before it runs
and blocks the ones that go after your credentials. It works in `bypassPermissions` and every other mode. MIT,
no telemetry, no dependencies beyond Node.js.

## Install

```sh
git clone https://github.com/IgorGanapolsky/agent-credential-guard
cd agent-credential-guard
bin/mac-yolo-credential-guard install --agent all
bin/mac-yolo-credential-guard doctor
```

`install` copies the guard to `~/.local/share/mac-yolo-safeguards/` and adds it to each agent's hook
settings. A copy of each settings file is saved first. `uninstall --agent all` removes it. `doctor` lists what
may already be on your Mac: credential copies in temp folders, secrets in the launchd environment, auto-approve
settings, and hooks that run inline code.

Try a command without installing anything:

```sh
bin/mac-yolo-credential-guard check -- security dump-keychain
```

## What it blocks

Each rule maps to a MITRE ATT&CK technique and can be set to `block`, `warn`, `log` or `ask`.

| Rule | Example it catches | ATT&CK |
| --- | --- | --- |
| `keychain` | `security find-generic-password`, `dump-keychain`, `export`, Python `keyring` | T1555.001 |
| `browser-store` | Chrome, Brave, Edge, Arc, Safari and Firefox cookie and login files | T1555.003 |
| `cookie-library` | `browser_cookie3`, `pycookiecheat`, `rookiepy` | T1539 |
| `quarantine` | `xattr -d com.apple.quarantine` | T1553.001 |
| `launchctl-secret` | `launchctl setenv` with a secret-looking name | T1552 |
| `pipe-to-shell` | `curl ... \| bash` and its disguises | T1059.004 |
| `net-oneliner` | `python3 -c` or `node -e` code that opens a socket | T1059 |
| `tmp-exec` | running a program from `/tmp` | T1204.002 |
| `launch-agent` | writing a LaunchAgent (asks you first) | T1543.001 |
| `tcc` | `tccutil` and `TCC.db` | T1548.006 |

The full list, the settings file and every edge case are in [docs/CREDENTIAL-GUARD.md](./docs/CREDENTIAL-GUARD.md).

A grep, a doc or a commit message that only *mentions* these commands is allowed. The rules look at the
program each part of a command runs, not at the words.

## Ask mode

With a rule set to `ask`, the call is denied until you approve that exact call. The match is a SHA-256 digest
of its tool, arguments, paths and working folder, so a changed argument needs a new approval. Agents cannot
approve their own calls.

## Audit log

Every hit is one JSON line in `~/Library/Logs/mac-yolo/credential-guard.jsonl`, with the rule, the ATT&CK
technique, the agent and whether the call ran. It keeps the program names and flags but no argument values,
file names or hosts, so it is safe to send to a SIEM. [tools/mac-yolo-falcon-export.js](./docs/falcon-logscale-export.md) sends it to CrowdStrike
Falcon LogScale.

## Siren on a Mac

Anthropic's [Siren study](https://safeguards.anthropic.com/2026/siren/) (Nov 2026) found that recent Claude
models reach outside a sandbox in 21% to 32% of tempting scenarios, that wording like "you have full authority"
raises that by up to 26 points, and that shell-only checks miss product tools such as file readers. Siren tested
Linux sandboxes. On a Mac in YOLO mode there is usually no sandbox, so the honeypots are simply there.

This guard sees every tool call (Read, Grep, Edit, Write, NotebookEdit, not only Bash), and it never reads
free-text fields, so wording cannot change a verdict. `tests/test-mac-yolo-credential-guard-siren.js` checks
both. [docs/SIREN-ON-A-MAC.md](./docs/SIREN-ON-A-MAC.md) maps each finding to macOS, gives six boundary rules to
paste into `CLAUDE.md` or `AGENTS.md`, and lists the gaps that remain.

## What it cannot do

The hook sees the command an agent asks to run, not what a program does after it starts. A compiled binary that
reads the keychain by itself gets past it. Use it as a seatbelt alongside a sandbox (Docker Sandboxes, Agent
Safehouse, Claude Code's `/sandbox`), not instead of one.

## Tests

```sh
npm test
```

`tests/test-mac-yolo-credential-guard-installed.js` installs into a temporary home and runs the exact hook
command the agent would run, so a guard that only works from this checkout fails the build.

Tests run as a normal user. As root, the one check that a read-only folder blocks a write cannot fail, so it
reports a false failure.

## Security

Report a way past the guard privately; see [SECURITY.md](./SECURITY.md), which also lists what the guard does not
protect.

Part of [Mac YOLO Safeguards](https://macyolosafeguards.io), a menu bar app that cleans up the agent processes
and MCP servers that pile up on a Mac.
