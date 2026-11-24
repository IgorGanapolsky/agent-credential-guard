# Falcon LogScale export

`tools/mac-yolo-falcon-export.js` sends the credential-guard block log to CrowdStrike Falcon Next-Gen SIEM / LogScale using
[structured ingest](https://library.humio.com/logscale-api/api-ingest-structured-data.html). Node only, no dependencies.

This project is not affiliated with or endorsed by CrowdStrike.

## What it sends

One event per row of `~/Library/Logs/mac-yolo/credential-guard.jsonl`, in requests of at most 500 events, to
`POST <MAC_YOLO_FALCON_URL>/api/v1/ingest/humio-structured` with `Authorization: Bearer <token>`. Tags are
`source=mac-yolo-safeguards` and `host=<hostname>`. Attributes: `rule`, `ruleId`, `attackTechniqueIds` (MITRE ATT&CK),
`agent`, `denied`, `reason` (the rule's fixed description), `mode`, `tool`, and `policyVersion` when the log row has one.

It never sends command lines, file contents, environment, or any field named `command`, `args`, `env`, `token` or
`secret`; only the fields above are copied, and the home directory is replaced by `~` in text fields.

## Setup

```sh
export MAC_YOLO_FALCON_URL="https://<your LogScale or Falcon ingest host>"
export MAC_YOLO_FALCON_TOKEN="<ingest token>"   # environment only, never a flag
node tools/mac-yolo-falcon-export.js
```

Flags: `--log <file>`, `--since <ISO date>`, `--dry-run`. With no URL set it is always a dry run: it prints the request
bodies (an array, one body per request) and sends nothing. The default start point is a cursor file,
`~/.local/state/mac-yolo/falcon-export.cursor`, which moves only after a 2xx response. A non-2xx response exits 1 and
prints the status code only.

## Sample event

```json
{
  "timestamp": "2026-11-19T14:01:00.000Z",
  "attributes": {
    "rule": "keychain",
    "ruleId": "keychain",
    "attackTechniqueIds": ["T1555.001"],
    "agent": "claude",
    "denied": true,
    "reason": "reads the macOS keychain",
    "mode": "block",
    "tool": "Bash"
  }
}
```

Tests: `node tests/test-mac-yolo-falcon-export.js`.
