#!/usr/bin/env node
'use strict';

// Sends the credential-guard log to CrowdStrike Falcon Next-Gen SIEM / LogScale (structured ingest).
// Not affiliated with or endorsed by CrowdStrike. See docs/falcon-logscale-export.md.
//
//   MAC_YOLO_FALCON_URL=https://<ingest host> MAC_YOLO_FALCON_TOKEN=<ingest token> node tools/mac-yolo-falcon-export.js
//   flags: --log <file>  --since <ISO>  --dry-run
//
// With no URL set, or with --dry-run, it prints the request body and sends nothing. The token is read only from the
// environment and is never printed. The cursor moves only after a 2xx.

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');

const BATCH = 500;
const SOURCE = 'mac-yolo-safeguards';
const SENSITIVE = /^(command|args|env|token|secret)$/i;

let RULES = {};
try { RULES = require('./mac-yolo-credential-guard').RULES || {}; } catch { /* export still works without rule reasons */ }

function parseArgs(argv) {
  const out = { dryRun: false, log: null, since: null, problems: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--dry-run') out.dryRun = true;
    else if (a === '--log' || a === '--since') {
      if (argv[i + 1] === undefined) out.problems.push(`${a} needs a value`);
      else out[a.slice(2)] = argv[++i];
    } else out.problems.push('unknown argument (flags: --log, --since, --dry-run)');
  }
  if (out.since && Number.isNaN(Date.parse(out.since))) out.problems.push('--since is not an ISO date');
  return out;
}

/** Turns one guard-log row into a LogScale event, keeping only known safe fields. Returns null for unusable rows. */
function toEvent(row, home) {
  if (!row || typeof row !== 'object' || Number.isNaN(Date.parse(row.at))) return null;
  const clean = Object.fromEntries(Object.entries(row).filter(([k]) => !SENSITIVE.test(k)));
  const ruleId = String(clean.ruleId || clean.rule || '');
  const techniques = [].concat(clean.techniques || clean.technique || (RULES[ruleId] && RULES[ruleId].technique) || [])
    .filter((t) => typeof t === 'string' && /^T\d{4}(\.\d{3})?$/.test(t));
  const reason = clean.reason || (RULES[ruleId] && RULES[ruleId].reason) || undefined;
  const scrub = (s) => (typeof s === 'string' && home ? s.split(home).join('~') : s);
  const attributes = {
    rule: ruleId,
    ruleId,
    attackTechniqueIds: techniques,
    agent: scrub(String(clean.agent || 'unknown')),
    denied: clean.denied === true,
    reason: scrub(reason),
    mode: clean.mode,
    tool: scrub(clean.tool),
    policyVersion: clean.policyVersion || clean.policy_version || clean.policy,
  };
  for (const k of Object.keys(attributes)) if (attributes[k] === undefined || attributes[k] === '') delete attributes[k];
  return { timestamp: new Date(row.at).toISOString(), attributes };
}

function readEvents(file, since, home) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const floor = since ? Date.parse(since) : -Infinity;
  const events = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const ev = toEvent(row, home);
    if (ev && Date.parse(ev.timestamp) > floor) events.push(ev);
  }
  return events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}

function buildBodies(events, host) {
  const bodies = [];
  for (let i = 0; i < events.length; i += BATCH) {
    bodies.push([{ tags: { source: SOURCE, host }, events: events.slice(i, i + BATCH) }]);
  }
  return bodies;
}

function ingestUrl(base) {
  return `${base.replace(/\/+$/, '')}/api/v1/ingest/humio-structured`;
}

/** Real sender: resolves with the HTTP status code only. */
function httpSend(url, token, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === 'http:' ? http : https).request(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      timeout: 30000,
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

async function run(argv, env, deps = {}) {
  const home = deps.home || os.homedir();
  const out = []; const err = [];
  const result = (code) => ({ code, stdout: out.join(''), stderr: err.join('') });
  const args = parseArgs(argv);
  if (args.problems.length) { err.push(`mac-yolo-falcon-export: ${args.problems.join('; ')}\n`); return result(2); }

  const logFile = args.log || path.join(home, 'Library', 'Logs', 'mac-yolo', 'credential-guard.jsonl');
  const cursorFile = deps.cursorFile || path.join(home, '.local', 'state', 'mac-yolo', 'falcon-export.cursor');
  let since = args.since;
  if (!since) { try { since = fs.readFileSync(cursorFile, 'utf8').trim() || null; } catch { since = null; } }

  const events = readEvents(logFile, since, home);
  const bodies = buildBodies(events, deps.host || os.hostname());
  const base = env.MAC_YOLO_FALCON_URL;
  const token = env.MAC_YOLO_FALCON_TOKEN;

  if (args.dryRun || !base) {
    out.push(`${JSON.stringify(bodies.length ? bodies : [], null, 2)}\n`);
    if (!args.dryRun) err.push('mac-yolo-falcon-export: MAC_YOLO_FALCON_URL not set, dry run only\n');
    return result(0);
  }
  if (!token) { err.push('mac-yolo-falcon-export: MAC_YOLO_FALCON_TOKEN not set\n'); return result(2); }

  const send = deps.send || httpSend;
  const url = ingestUrl(base);
  let sent = 0;
  for (const body of bodies) {
    let status;
    try { status = await send(url, token, body); } catch { err.push('mac-yolo-falcon-export: request failed\n'); return result(1); }
    if (!(status >= 200 && status < 300)) { err.push(`mac-yolo-falcon-export: HTTP ${status}\n`); return result(1); }
    sent += body[0].events.length;
    const last = body[0].events[body[0].events.length - 1].timestamp;
    fs.mkdirSync(path.dirname(cursorFile), { recursive: true });
    fs.writeFileSync(cursorFile, `${last}\n`, { mode: 0o600 });
  }
  out.push(`mac-yolo-falcon-export: sent ${sent} events in ${bodies.length} requests\n`);
  return result(0);
}

if (require.main === module) {
  run(process.argv.slice(2), process.env).then((r) => {
    process.stdout.write(r.stdout); process.stderr.write(r.stderr); process.exitCode = r.code;
  });
}

module.exports = { run, toEvent, buildBodies, parseArgs, ingestUrl, BATCH };
