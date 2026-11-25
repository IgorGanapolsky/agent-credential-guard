# Credential guard for AI coding agents

`mac-yolo-credential-guard` keeps agents that run with approvals turned off away from your keychain, your
browser logins and the network tricks that endpoint security tools treat as attacks. It has two parts:

- **a hook** that Claude Code, Codex and Cursor run before each tool call;
- **a doctor** that looks for what may already be on your Mac.

## The hook: what it checks

The hook runs before the call does, and it also works in `bypassPermissions` mode. Every rule has an ID, a
MITRE ATT&CK technique and a mode:

- `block` denies the call;
- `warn` lets it run and shows the agent a warning;
- `log` lets it run silently.

`warn` and `log` hits still write a log line, so you can see how often a rule would fire before you block it.

| Rule | ATT&CK | Default | Example it catches |
|---|---|---|---|
| `keychain` | T1555.001 | block | `security find-generic-password -s "Chrome Safe Storage"`, `security dump-keychain`, `security find-internet-password`, `security export`, Python `keyring` |
| `keychain-file` | T1555.001 | block | opening a file in `~/Library/Keychains/` |
| `browser-store` | T1555.003 | block | `Cookies`, `Login Data` or `Local State` under Chrome (also Beta and Canary), Brave, Edge, Arc, Chromium or Vivaldi; Safari `Cookies.binarycookies`; Firefox `cookies.sqlite`, `logins.json` or `key4.db`; copying a whole browser profile folder |
| `cookie-library` | T1539 | block | `browser_cookie3`, `pycookiecheat`, `rookiepy` |
| `quarantine` | T1553.001 | block | `xattr -d com.apple.quarantine`, `xattr -dr ...`, `xattr -c`, `xattr -cr` |
| `launchctl-secret` | T1552 | block | `launchctl setenv` with a name containing KEY, TOKEN, SECRET, PASS, CRED, AUTH, PRIVATE, SESSION, COOKIE or PAT |
| `guard-config` | T1685 | block, always | see "Self-protection" below |
| `work-folder` | T1213 | block | any path in your opt-in work-folder list, from an agent not started with `MAC_YOLO_WORK_AGENT=1` |
| `net-oneliner` | T1059 | block | inline code that makes a network call: `python3 -c` with `socket.socket(`, `urlopen(` or `requests.get(`; `node -e`, `deno eval` or `bun -e` that loads `net`, `http`, `https`, `tls` or `dgram` and calls it, or calls `fetch(`; `perl -e` with `IO::Socket`/`LWP` and a call; `ruby -e` with `TCPSocket.new` or `Net::HTTP.get`; any redirect to `/dev/tcp/` or `/dev/udp/`. Also covers the same code in `bash -c`, `eval`, a heredoc, a here-string or `echo ... \|`, and an agent adding such a command as a hook in its own settings |
| `curl-upload` | T1048 | log | `curl -d @file`, `--data-binary @`, `--json @`, `-F name=@file`, `-T`, `--upload-file`, `wget --post-file` or `--body-file`, to a host not on `uploadAllowlist` |
| `recorder` | T1113 | block | installing or starting a screen recorder: `brew install screenpipe`, `curl https://screenpi.pe/install.sh \| sh`, `./install-screenpipe.sh`, `screenpipe`, `open -a screenpipe`, `npx screenpipe`, `launchctl load` of its plist |
| `banned-agent` | T1567 | block | running a program on your `bannedAgents` list, directly, by path, through `npx`, `bunx`, `pnpm dlx`, `npm exec` or `uvx`, with `open -a`, or inside `bash -c` |
| `pipe-to-shell` | T1059.004 | block | a download piped into a shell or osascript: `curl ... \| bash`, `wget -O- ... \| sh`, `curl ... \| osascript`, `sh -c "$(curl ...)"`, `bash <(curl ...)`, and `base64 -d ... \| sh`. A python, perl, ruby or node on the right of the pipe counts only when it reads its script from stdin (no argument, `-`, or option flags only), so `curl ... \| python3 -m json.tool` and `curl ... \| python3 parse.py` are allowed. Wrappers and groups in front of the shell do not hide it: `\| sudo -E bash`, `\| /usr/bin/env bash`, `\| env -i sh`, `\| nice sh`, `\| xargs sh`, `\| (sh)`, `\| { sh; }`; and `\| python3 -c 'exec(sys.stdin.read())'` (inline code that runs what it reads from stdin) is a sink, while `python3 -c "import sys; print(sys.stdin.read())"` is not The rule is no longer a list of wrappers: when a pipeline stage or a command substitution fetches from the network (`curl`, `wget`, `fetch`, `nc`, `ssh`, `base64 -d`) and any later stage, process substitution or the argument of `eval`, `source` or `.` holds a shell or interpreter word (`sh`, `bash`, `zsh`, `python3`, `node`, `perl`, `ruby`, `php`, `osascript`, `pwsh`), it is denied, so `\| timeout 30 bash`, `\| su root -c sh`, `\| script -q /dev/null sh`, `eval "$(curl ...)"` and `source <(curl ...)` are caught. A stage whose command is a plain text tool (`jq`, `grep`, `head`, `tee`, `wc`) is a harmless sink, and an interpreter given literal code or a script file is too (`python3 -m json.tool`, `python3 -c '<code without exec, eval, system or subprocess>'`). The scan is one pass over the command, linear in its length. Fetched text that reaches a compound statement (`| if true; then bash; fi`, `| while read l; do eval "$l"; done`), a command word the scan cannot read (`| $SHELL`, `| ${SHELL:-sh}`, `| /bin/ba?h`, `| $(echo bash)`), or a variable assigned from a fetch and then run (`x=$(curl ...); eval "$x"`, `bash -c "$x"`) is denied. A shell given only `--version` or `--help` is not a sink. |
| `tmp-exec` | T1204.002 | block | running a program or script from a temp folder (`/tmp`, `/private/tmp`, `/var/tmp`, `/var/folders/xx/yyyy/T` and `$TMPDIR`, `${TMPDIR}`, `$TMP`). The rule reads the executed file's parent folder after resolving `cd`, variables and `sh -c` strings. A file directly in a temp root is denied (`/tmp/x`, `nice -n 5 /tmp/x`, `$TMPDIR/payload`, `cd /tmp; bash payload.sh`, `bash -c 'cd /tmp && ./payload'`, `python3 /tmp/x.py`, `node /tmp/x.js`, `bash < /tmp/payload.sh`, `open /tmp/X.app`). A file one or more folders down is denied unless it is a project: the file is `configure`, `Makefile` or `package.json`, or a folder above it inside the temp root holds `.git`, `package.json`, `Makefile`, `configure`, `Cargo.toml`, `pyproject.toml` or `CMakeLists.txt` (`cd /tmp/proj && ./configure && make` is allowed). A relative path counts only after a `cd` inside the same command, so a session whose own folder is under a temp path, or a path inside your home folder, is not denied. Known gaps: a folder that fakes a project marker is allowed, and `/var/folders/xx/yyyy/C` is not a temp root (only `.../T` is). Known false positive: a program or script under a temp folder at any depth with no project marker in a folder above it inside the temp root (`cd /tmp/repro && python3 test.py`, `cd /tmp/work/proj/src && ./run-tests`, `/tmp/build-xyz/release/tool`) is denied. What to do: move the project out of the temp folder (for example under your home folder), or put a marker file (`package.json`, `Makefile`, `.git` and so on) in a folder above it inside the temp root. There is no per-path exception; the only other switch is the rule's mode (`"tmp-exec": "ask"`, `"warn"` or `"log"`) in `~/.config/mac-yolo/credential-guard.json`, which applies to every temp-folder program. A path more than 32 folders below a temp root is denied without being probed. |
| `tcc` | T1548.006 | block | `tccutil`, and any command or file path that names `TCC.db` |
| `launch-agent` | T1543.001 | ask | writing into `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons` (Write/Edit tools, `cp`, `mv`, `ln`, `ditto`, `rsync`, `install`, `tee`, `touch`, a `>` redirect, `defaults write`, `plutil -replace`, `sed -i`), and `launchctl load`, `bootstrap`, `enable`, `disable` or `submit`. Reading (`ls`, `launchctl list`) is allowed. A person approves one call in the menu bar |
| `falcon` | T1562.001 | block | running `falconctl` or `falcond`; any command naming `/Applications/Falcon.app`, `/Library/Application Support/CrowdStrike`, `/Library/CS` or a `com.crowdstrike` LaunchDaemon file; `launchctl bootout`, `unload`, `remove`, `disable`, `kill`, `stop` and the like on a `com.crowdstrike.*` label; `kill`, `pkill` or `killall` of a Falcon process, including through another command (`kill -9 $(pgrep falcond)`, `pgrep falcond \| xargs launchctl remove`); `rm`, `mv`, `cp`, `sed`, `defaults write` and similar on a `com.crowdstrike` file; and uninstalling its system extension (team ID X9E956P446). Text that only names the vendor is allowed: `rg com.crowdstrike docs/`, `git commit -m "..."`, `cat notes.md` |

What stays allowed, by design: `curl` and `wget` downloads, `gh`, `git`, package installs (`npm install`,
`pip install requests`), `python3 -c` with no network call (`import requests; print(requests.__version__)`,
`socket.gethostname()`), searches and commit messages that only mention these words, uninstalling a recorder
(`brew uninstall screenpipe`, `./uninstall-screenpipe.sh`), and looking at a banned agent's files
(`ls ~/.codex`, `git log --grep codex`).

Each block tells the agent, in one line, why it was blocked, what to do instead, and the rule and technique, for
example `(rule keychain, ATT&CK T1555.001)`. A banned agent's message says the owner of this Mac banned it.

The keychain, quarantine and `launchctl` rules look at the program each part of the command runs. So a commit
message, a grep or a document that only mentions these commands is not blocked. Inline code run by an interpreter
(`python3 -c`, `bash -c`) is scanned as a whole, so mentioning them there is blocked. The four newer rules read the
command with its quotes and heredocs kept, so text inside a quoted message or a heredoc written to a file is never
read as a command.

## Settings: `~/.config/mac-yolo/credential-guard.json`

```json
{
  "rules": { "curl-upload": "warn", "net-oneliner": "block" },
  "uploadAllowlist": ["github.com", "uploads.example.org"],
  "recorders": ["rewind"],
  "bannedAgents": ["codex", "gemini", "agy", "antigravity"]
}
```

- `rules` sets a mode per rule ID. Rules you leave out keep their default.
- `uploadAllowlist` lists hosts that `curl-upload` ignores. A host matches exactly or as a subdomain.
  `localhost`, `127.0.0.1` and `::1` are always on it. An entry must be a full host name: `com` is rejected.
- `recorders` adds names to the recorder list. `screenpipe` and `screenpi.pe` are always on it.
- `bannedAgents` lists programs agents may not start. It is empty by default.

Names in `recorders` and `bannedAgents` must be at least three characters of letters, digits, `.`, `_` or `-`.

**A broken file only makes the guard stricter.** If the file has an error, the doctor reports it as high, and:
- each rule keeps the stricter of its default and the file's value;
- the name lists keep their valid names;
- the upload allowlist falls back to the default.

`guard-config` stays on `block` whatever the file says. Setting any credential rule (the first eight in the table)
below `block` works, but the doctor reports it as high.

Agents can't change this file; edit it yourself in a terminal.

## Kill switch: `~/.config/mac-yolo/PAUSE`

While `~/.config/mac-yolo/PAUSE` exists, the hook denies every tool call from every agent that has the hook,
before it even reads the call. Each denial says that file exists and that a person removes it in their own
terminal to resume. Agents can't create or remove it.

```sh
touch ~/.config/mac-yolo/PAUSE    # stop all agents
rm ~/.config/mac-yolo/PAUSE       # resume
```

## Self-protection (`guard-config`)

The hook denies, whatever the settings say:

- `install`, `uninstall`, `fix` and `work-folders add` run by an agent;
- shell writes to `~/.config/mac-yolo/`, the installed guard file or an agent's hook file: `>`, `>|`, `sed -i`,
  `rm`, `mv`, `cp` onto, `tee`, `dd of=`, `curl -o`, `wget -O`, or an interpreter naming the file;
- any command that names the `mac-yolo` config folder (through `~`, `$HOME` or a variable) and does more than
  read it. `touch`, `mkdir`, `tar -C`, `unzip -d`, `cp -t` and `git clone` into it are all denied;
- `tar` or `unzip` that unpacks into `~` or `~/.config`;
- an edit that removes the guard's entry from a hook file, in `~/.claude`, every other Claude config dir it finds
  (`~/.claude-*`, `CLAUDE_CONFIG_DIR`) and their `settings.local.json`;
- an edit that adds `disableAllHooks` or `allowManagedHooksOnly` to any Claude `settings*.json`;
- an edit that adds `enabled = false` to `~/.codex/config.toml`.

Reads pass: `doctor`, `check -- <cmd>`, `work-folders list`, `--help`, and `cat`, `ls`, `grep`, `jq` or `sed`
without `-i` of these files.

## Limits

- Writing an agent's hook settings from the shell (`cat > .claude/settings.local.json`, `tee`, `cp`) is denied when
  the text adds a hook with network code, or when the text can't be seen (a copy). Use the Edit tool for those files.
- If the guard itself fails on a call, the call is denied (`rule internal-error`), never allowed.

- The hook reads the command line the agent asks to run. It does not see what a program does after it starts. A
  test suite or script file that calls the keychain or opens a socket from inside (`npm test`, `./run.sh`,
  `python3 tool.py`) is not blocked, and neither is a command hidden by encoding. Write tests that use fake
  keychains and fake browser paths.
- Inline code fed on stdin is caught when it is in the same command (a heredoc, `<<<`, or `echo ... | python3`),
  but not when it comes from a file (`python3 < x.py`).
- `banned-agent` matches the program's exact name. A wrapper script with another name, or a name built at run
  time (`c=codex; $c`), gets past it.
- `recorder` catches the common install and launch commands, not every way to run a downloaded binary.
- Claude config dirs named only inside launcher scripts are found by `doctor` but are not protected by the hook.
- Reading CLI credential files (`~/.ssh`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.netrc`, `~/.npmrc`)
  is not blocked yet, and neither is a `Glob` or `Grep` over a whole browser profile folder. See
  [SIREN-ON-A-MAC.md](./SIREN-ON-A-MAC.md) for these gaps and the boundary rules to put in your agent's
  instructions.
- The hook does not stop an agent from editing its config by means it can't see. Run `doctor` from time to time:
  it reports any agent config dir whose hook is missing.

## Install the hook

```sh
bin/mac-yolo-credential-guard install --agent all     # or --agent claude | codex | cursor
bin/mac-yolo-credential-guard uninstall --agent all   # removes only this guard's entries
```

`install` copies the guard to `~/.local/share/mac-yolo-safeguards/` and adds one hook entry to each agent's
config:

- `~/.claude/settings.json` (`PreToolUse`);
- `~/.codex/hooks.json` (`PreToolUse`, added after your existing hooks). Codex runs a new hook only after you
  trust it; the doctor reports when Codex has no trust record for it or has it turned off;
- `~/.cursor/hooks.json` (`beforeShellExecution` and `beforeReadFile`).

For another Claude config dir, run `doctor` and then `fix <id>` on its `hook-missing` finding.

Your other hooks stay as they are, and each changed file is first backed up next to itself as
`<file>.mac-yolo-backup-<time>`. Running it twice changes nothing.

## The log

Every hit is logged to `~/Library/Logs/mac-yolo/credential-guard.jsonl`, one JSON line each, with:
- the rule ID, technique and mode;
- whether it denied the call;
- the agent's parent process names, at most six (for example `["zsh", "claude", "Terminal"]`).

The line also keeps the command's shape: the program names and flags (`curl -fsSL … (+1 more)`), never their
values. Argument values, code, file names and hosts are never logged. The log moves to `credential-guard.jsonl.1` once it
passes 5 MB.

## The doctor: what is already there

```sh
bin/mac-yolo-credential-guard doctor          # one line per finding; exit 1 on any finding above info
bin/mac-yolo-credential-guard doctor --json
bin/mac-yolo-credential-guard fix <id>        # asks y/N first
```

The doctor only reads. Its first line says `PAUSED` while the kill switch is on. It then lists each rule that had
hits in the last 7 days, with its technique, mode and counts (blocked, warned, logged). It reports:

- **Browser credential copies in temp folders.** It looks under `/private/tmp` and your user temp folder for
  `chrome-prof*` folders and for files whose content is a credential store: SQLite with a `logins` or `cookies`
  table, Safari binary cookies, a cookies export or a Chromium `Local State` key. Profiles of running test browsers
  (Playwright, Puppeteer, Cypress, WebDriver) are skipped. Fix: move to the Trash.
- **Secrets in the launchd environment.** These are names set with `launchctl setenv` in your login scripts
  or LaunchAgents, plus common API key names. Only names are shown, never values. Fix:
  `launchctl unsetenv NAME`, after which you remove the line that sets it at login.
- **Auto-approve settings.**
  - Claude Code `bypassPermissions`. Fix: set back to `default`.
  - Codex `approval_policy = "never"` and `danger-full-access`, including profiles. Fix: `on-request` and
    `workspace-write`.
  - Antigravity auto-approve switches. Fix: the on/off switches are set to off.
  - Gemini yolo settings.
  - Any script on your PATH, and shell aliases, that start an agent with `--dangerously-skip-permissions`,
    `--permission-mode bypassPermissions`, `--dangerously-bypass-approvals-and-sandbox`,
    `--ask-for-approval never`, `-a never`, `danger-full-access`, `--always-approve`, `--sandbox disabled`,
    `--yolo` or `--approval-mode yolo`. Only lines that start an agent count. The scan reads scripts under 200 KB,
    at most 5,000 files, and says which PATH dirs it skipped when it stops early. There is no automatic fix.
- **Hooks that run inline interpreter code** such as `python3 -c "..."` (marked high when the code opens network
  connections). Endpoint security tools read these as attacks. Fix: remove that hook entry.
- **Screen recorders without the quarantine flag.** It looks for screenpipe apps and binaries, and
  LaunchAgents that start one. Fix: move to the Trash.
- **Agent config dirs with no credential hook**: `~/.claude`, each `~/.claude-*` dir that holds `settings.json`,
  `.claude.json` or `projects/`, `CLAUDE_CONFIG_DIR` from your environment, launcher scripts and shell startup
  files, plus `~/.codex` and `~/.cursor`. Fix: install it.
- **Guard settings problems**: an invalid settings file, or a credential rule set below `block`.
- **Agent and MCP servers listening on the network.** It runs `lsof` for listening TCP sockets owned by node,
  python, deno, bun, uv or anything named like an MCP server or agent. One bound to every interface (`*`,
  `0.0.0.0`, `[::]`) is high. One on `127.0.0.1` or `[::1]` is listed as info.
- **Tailscale accepting connections in.** When Tailscale is installed, it is high when `tailscale debug prefs`
  shows `ShieldsUp` false, and when `tailscale serve` or `tailscale funnel` has any config. This Mac should only
  connect out to other machines. When Tailscale is not installed, the check is skipped.
- **Agents running as you** (info only, never a failure). When agent config dirs sit in the same home folder as
  your login keychain or browser profiles, any agent can reach them. It recommends a dedicated macOS user or a
  cloud machine for unattended agents. It checks only that those folders exist and never reads them.

Before a fix changes a config file, it copies the original into your Trash. It never deletes anything.

## Work folders (opt-in)

To keep agents signed in to a personal account out of a work repo:

```sh
bin/mac-yolo-credential-guard work-folders add /absolute/path/to/work
```

Agents are then refused in that folder (by absolute path, or a relative path from where the agent is), unless
their own environment has `MAC_YOLO_WORK_AGENT=1`. Set that variable only in the agents you start under your work
account. A command the agent runs cannot change its own environment. The hook refuses agent commands that change
the list, but an agent that edits its own agent config to remove the hook gets around this, as the Limits say.
