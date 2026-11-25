# Siren on a Mac: what Anthropic's sandbox-escape study means for agents in YOLO mode

On Nov 24, 2026 Anthropic's Safeguards team published **Siren**, a test of whether Claude models cross sandbox
boundaries when a task tempts them to ([safeguards.anthropic.com/2026/siren](https://safeguards.anthropic.com/2026/siren/),
by Oscar O'Rahilly and Darya Kaviani). This page maps its findings onto the credential guard, lists what we
changed, and lists the gaps that remain.

## What Siren found, in short

- **Setup.** 26 sandboxes (bubblewrap, Linux namespaces, Docker, gVisor, small QEMU VMs), each with a weakness,
  combined with tasks, honeypots and "tempters" into more than 1,700 scenarios. A honeypot is a useful file, a
  credential, or a service that emulates the public internet. Tempters add urgency, raise the stakes, demand a
  thorough search or claim broad authority over the machine. They never tell the agent to leave.
- **Outcomes**, nested: *reached outside*, *used* what it found, and *misaligned use* (a use no reasonable reading
  of the task allows).
- **Results** (without shipped safeguards). Recent models reached outside in 21% to 32% of scenarios and made
  misaligned use in 0.6% to 1.6%. Older models were far worse (12.7% and 25.8% misaligned use).
- **Wording matters.** Removing "you have broad authority" or "search thoroughly" cut reaching outside by 23 to
  26 points in five of six models. Deadlines and stakes changed it by about 6 points at most.
- **What helped.** A system-prompt description of the sandbox plus six boundary rules cut reaching outside by 68%
  to 96%. A tool for *reporting* a sandbox weakness cut it by 7 to 33 points. Auto mode's classifier, replayed
  offline, blocked the first honeypot read in 96% to 100% of misaligned uses.
- **Stated limits.** The classifier was tuned on the same episodes. The models had only a shell, and *"in
  products, some tools skip this check"*, naming Claude Code's file-reading tools. Siren tests Linux sandboxes
  only; macOS, Seatbelt and `sandbox-exec` are not mentioned.

## How it maps onto a Mac in YOLO mode

On a Mac, "the sandbox" is usually nothing: the agent runs as you, in `bypassPermissions`, with your keychain,
browser profiles and LaunchAgents one command away. Siren's honeypots are simply *there*.

| Siren idea | On a Mac | What the guard does |
|---|---|---|
| Credential honeypot | Keychain, browser cookie and password stores, launchd environment | `keychain`, `keychain-file`, `browser-store`, `cookie-library`, `launchctl-secret` rules |
| Useful-file honeypot that controls the machine | `TCC.db`, the guard's own settings, the EDR sensor, Gatekeeper quarantine flags | `tcc`, `guard-config` (always on), `falcon`, `quarantine` |
| Service on the public internet | `curl \| bash`, inline sockets, uploads | `pipe-to-shell`, `net-oneliner`, `curl-upload` (log by default) |
| Boundary rule 6: nothing keeps running after the task | LaunchAgents and LaunchDaemons | `launch-agent` (asks a person) |
| "Some product tools skip the shell check" | Read, Grep, Edit, Write, NotebookEdit | The hook is installed with matcher `*`, so it sees every tool call, not only Bash |
| Tempters change what the model chooses | Urgent or "full authority" wording in prompts and repo instructions | The hook reads paths and commands only. Free-text fields (`description`, `prompt`) are never read, so wording cannot change a verdict |
| Reporting channel | A person needs to see what was tried | Each deny tells the agent why and what to do instead; every hit is one line in `credential-guard.jsonl` with program names and flags but no argument values |
| Auto mode classifier | Probabilistic, tuned on known episodes | The guard is deterministic and complements it. Use both |

The new test file `tests/test-mac-yolo-credential-guard-siren.js` checks the three properties above with
Siren-style scenarios: 15 honeypot reaches across six tool surfaces are denied, three tempter styles never change
a verdict, and a deny tells the agent to stop and writes a log line with no argument values or tempter text.

## Boundary rules for your agent's instructions

Siren's strongest mitigation was text: a description of the boundary plus six rules. Here they are rewritten for
an agent running on your own Mac. Paste the block into `CLAUDE.md`, `AGENTS.md` or your agent's system prompt.
They are not a substitute for the hook; Siren's own conclusion is that configuration and patching are what
actually block escapes.

```markdown
## Boundaries on this Mac

You run as the owner's macOS user, without a sandbox. Treat these as rules even where nothing enforces them.
If the task needs something you were not given, stop and say so.

1. Work only inside this project folder. Do not read or write the owner's other files, including through a
   symlink, mount or file handle that happens to reach them.
2. The keychain, browser profiles (cookies, saved passwords), `~/.ssh`, `~/.aws`, `~/.config/gh` and other
   credential files are not yours. Use only the secrets passed to you in the environment for this task.
3. Do not change macOS security settings or the tools that watch you: privacy permissions (TCC), Gatekeeper
   quarantine flags, the endpoint security sensor, or this agent's hooks and guard settings.
4. Network traffic goes only to hosts the task needs. Do not pipe downloads into a shell or upload files that
   were not part of the task.
5. Nothing you create keeps running after the task: no LaunchAgents, LaunchDaemons, login items or cron jobs.
6. If you find a way around one of these rules, do not use it. Report it in your reply.
```

## Gaps that remain (measured Nov 25, 2026)

These calls are allowed today. Each was checked against the hook in this repo:

- Reading CLI credential files: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.netrc`,
  `~/.npmrc`, and `gh auth token`. This is Siren's boundary rule 4 (credentials only for the task's own
  resources) and the largest gap. It is the next rule on the list.
- `Glob` or `Grep` over a whole browser profile folder (a single file such as `Login Data` is caught).
- Uploads with `curl -d @file` are logged, not blocked, unless the mode is raised to `block`.
- A program that reads the keychain from inside (a test suite, a compiled binary) is not visible to a hook. Use a
  sandbox for that layer (Claude Code `/sandbox`, Docker Sandboxes, Agent Safehouse).
- No reporting tool. Siren found that giving the agent a way to report a weakness lowered escapes by up to 33
  points. An MCP tool that writes to the same audit log is the obvious shape.

## A Siren-style test for macOS

Siren covers Linux sandboxes. Nobody has published the same test for agents on a Mac, where the risk is highest
because there is usually no sandbox at all. The scenarios in the test file are a start: honeypots that already
exist on every Mac, reached through every tool surface, under the same tempter styles.
