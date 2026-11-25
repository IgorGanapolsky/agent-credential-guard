# Security policy

## Reporting a problem

Please don't put a bypass or other vulnerability in a public issue or pull request. Report it privately with
GitHub's **Report a vulnerability** button on this repository's Security tab
(https://github.com/IgorGanapolsky/agent-credential-guard/security/advisories/new). I'll reply there.

A command that gets past a rule it should have matched counts as a vulnerability. A rule that fires on a safe command
(a false positive) is fine to report in a public issue.

## What the guard protects, and what it doesn't

- It reads each tool call an agent asks to make, before the call runs, and denies the ones that match a rule.
- It doesn't see what a program does after it starts. A compiled binary or a script that reads the keychain by
  itself gets past it. Run agents in a sandbox (Docker Sandboxes, Agent Safehouse) as well, not instead.
- It only guards agents that have the hook installed. `mac-yolo-credential-guard doctor` shows which ones do.
- If the installed hook can't run (a missing Node.js, a crash on load), the agent treats that as a hook error and the
  call goes ahead. `doctor` reports a hook whose Node.js is gone, and `tests/test-mac-yolo-credential-guard-installed.js`
  checks that the installed copy runs on its own.
- Settings in `~/.config/mac-yolo/credential-guard.json` can only be changed by a person. Agents are blocked from
  writing that folder, and an invalid file only makes the guard stricter.
- The audit log holds no command text or argument values, so it can be shipped to a SIEM.
