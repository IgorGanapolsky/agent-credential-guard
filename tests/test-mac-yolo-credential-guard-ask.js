'use strict';

// Tests for ask mode (per-call approvals), the promotion report and the policy digest in
// tools/mac-yolo-credential-guard.js. Every case hands a string to the hook on stdin: nothing here reads a
// credential or runs the command. Each test uses a temporary HOME.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const G = require(path.resolve(__dirname, '..', 'tools', 'mac-yolo-credential-guard.js'));
const BASE = fs.mkdtempSync(path.join(os.tmpdir(), 'mycg-ask-'));
const NOW = new Date('2026-11-19T15:00:00Z');

let n = 0;
function makeCtx(clock = { t: NOW }) {
  const home = path.join(BASE, `case-${n += 1}`, 'home');
  fs.mkdirSync(home, { recursive: true });
  const ctx = {
    home, env: {}, tmpRoots: [], pathDirs: [], appDirs: [], logDir: path.join(home, 'Library', 'Logs', 'mac-yolo'),
    nodePath: process.execPath, ppid: 0, run: () => ({ status: 1, stdout: '', stderr: '' }), now: () => clock.t,
  };
  return { ctx, home, clock };
}
const cfg = (home, obj) => {
  fs.mkdirSync(path.join(home, '.config', 'mac-yolo'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'mac-yolo', 'credential-guard.json'), JSON.stringify(obj));
};
const approvals = (home) => path.join(home, '.config', 'mac-yolo', 'approvals');
const logRows = (home) => fs.readFileSync(path.join(home, 'Library', 'Logs', 'mac-yolo', 'credential-guard.jsonl'), 'utf8')
  .trim().split('\n').map((l) => JSON.parse(l));
const hook = (ctx, command) => G.runHook(JSON.stringify({ tool_name: 'Bash', tool_input: { command } }), 'claude', ctx);
const CMD = 'security find-generic-password -s my-secret-service-name';
const pendingOf = (ctx) => G.listPending(ctx);
const askCtx = () => { const c = makeCtx(); cfg(c.home, { rules: { keychain: 'ask' } }); return c; };

test('ask mode: no approval denies and writes a redacted pending request', () => {
  const { ctx, home } = askCtx();
  const r = hook(ctx, CMD);
  assert.strictEqual(r.exitCode, 2);
  assert.match(r.stderr, /needs a person's approval/);
  assert.match(r.stderr, /menu bar/);
  const p = pendingOf(ctx);
  assert.strictEqual(p.length, 1);
  assert.strictEqual(p[0].rule, 'keychain');
  assert.match(p[0].digest, /^[0-9a-f]{64}$/);
  const text = fs.readFileSync(path.join(approvals(home), 'pending', `${p[0].digest}.json`), 'utf8');
  assert.ok(!text.includes('my-secret-service-name') && !text.includes('find-generic-password'), 'pending request holds no command text');
  const row = logRows(home)[0];
  assert.strictEqual(row.mode, 'ask');
  assert.strictEqual(row.denied, true);
  assert.strictEqual(row.ran, false);
});

test('ask mode: a valid approval allows the call once and marks the file used', () => {
  const { ctx, home } = askCtx();
  hook(ctx, CMD);
  const [p] = pendingOf(ctx);
  G.approve(ctx, p.digest);
  assert.deepStrictEqual(pendingOf(ctx), []);
  const r = hook(ctx, CMD);
  assert.strictEqual(r.exitCode, 0);
  const row = logRows(home).pop();
  assert.strictEqual(row.denied, false);
  assert.strictEqual(row.ran, true);
  assert.strictEqual(row.approvalId, p.digest.slice(0, 16));
  const used = JSON.parse(fs.readFileSync(path.join(approvals(home), `${p.digest}.used.json`), 'utf8'));
  assert.strictEqual(used.used, true);
  assert.ok(!fs.existsSync(path.join(approvals(home), `${p.digest}.json`)));
});

test('ask mode: an approval is for that exact call; a changed argument is denied', () => {
  const { ctx } = askCtx();
  hook(ctx, CMD);
  G.approve(ctx, pendingOf(ctx)[0].digest);
  const r = hook(ctx, `${CMD} -w`);
  assert.strictEqual(r.exitCode, 2);
  assert.strictEqual(pendingOf(ctx).length, 1, 'the changed call has its own pending request');
});

test('ask mode: a reused approval is denied', () => {
  const { ctx } = askCtx();
  hook(ctx, CMD);
  G.approve(ctx, pendingOf(ctx)[0].digest);
  assert.strictEqual(hook(ctx, CMD).exitCode, 0);
  assert.strictEqual(hook(ctx, CMD).exitCode, 2);
});

test('ask mode: an approval already marked used in its file is denied', () => {
  const { ctx, home } = askCtx();
  hook(ctx, CMD);
  const [p] = pendingOf(ctx);
  fs.mkdirSync(approvals(home), { recursive: true });
  fs.writeFileSync(path.join(approvals(home), `${p.digest}.json`), JSON.stringify({ digest: p.digest, approvedAt: NOW.toISOString(), used: true }));
  assert.strictEqual(hook(ctx, CMD).exitCode, 2);
});

test('ask mode: an approval over 10 minutes old is denied', () => {
  const clock = { t: NOW };
  const { ctx, home } = makeCtx(clock);
  cfg(home, { rules: { keychain: 'ask' } });
  hook(ctx, CMD);
  G.approve(ctx, pendingOf(ctx)[0].digest);
  clock.t = new Date(NOW.getTime() + 10 * 60 * 1000 + 1000);
  assert.strictEqual(hook(ctx, CMD).exitCode, 2);
});

test('ask mode: an approval just under 10 minutes old still works', () => {
  const clock = { t: NOW };
  const { ctx, home } = makeCtx(clock);
  cfg(home, { rules: { keychain: 'ask' } });
  hook(ctx, CMD);
  G.approve(ctx, pendingOf(ctx)[0].digest);
  clock.t = new Date(NOW.getTime() + 9 * 60 * 1000);
  assert.strictEqual(hook(ctx, CMD).exitCode, 0);
});

test('ask mode: an unreadable approvals folder fails closed', () => {
  const { ctx, home } = askCtx();
  // A file where the folder should be: every read under it fails with ENOTDIR (works the same when run as root).
  fs.writeFileSync(approvals(home), 'not a folder');
  const r = hook(ctx, CMD);
  assert.strictEqual(r.exitCode, 2);
  assert.match(r.stderr, /could not be read/);
  assert.strictEqual(logRows(home)[0].denied, true);
});

test('ask mode: approve works only for a pending digest', () => {
  const { ctx } = askCtx();
  assert.throws(() => G.approve(ctx, 'a'.repeat(64)), /no pending request/);
  assert.throws(() => G.approve(ctx, 'nope'), /64-character/);
});

test('promotion report counts would-have-blocked hits and overrides on a fixture log', () => {
  const { ctx, home } = makeCtx();
  cfg(home, { rules: { 'net-oneliner': 'log', recorder: 'warn', 'curl-upload': 'log', keychain: 'ask' } });
  const at = (days) => new Date(NOW.getTime() - days * 86400000).toISOString();
  const row = (rule, mode, days, extra = {}) => ({ at: at(days), agent: 'claude', tool: 'Bash', rule, technique: 'x', mode, denied: false, ran: true, ...extra });
  const rows = [
    row('net-oneliner', 'log', 1), row('net-oneliner', 'log', 2), row('net-oneliner', 'log', 3), row('net-oneliner', 'log', 4),
    row('net-oneliner', 'log', 9), // older than 7 days: not counted
    row('recorder', 'warn', 1), row('recorder', 'warn', 2), row('recorder', 'warn', 3), row('recorder', 'warn', 3, { approvalId: 'abc' }),
    row('curl-upload', 'log', 1), row('curl-upload', 'log', 2),
    row('keychain', 'ask', 1, { denied: true, ran: false }),
  ];
  fs.mkdirSync(ctx.logDir, { recursive: true });
  fs.writeFileSync(path.join(ctx.logDir, G.LOG_FILE), `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
  const report = G.promotionReport(ctx, G.loadSettings(ctx));
  const by = Object.fromEntries(report.map((r) => [r.id, r]));
  assert.deepStrictEqual([by['net-oneliner'].hits, by['net-oneliner'].overrides, by['net-oneliner'].suggestion], [4, 0, 'switch to block']);
  assert.deepStrictEqual([by.recorder.hits, by.recorder.overrides, by.recorder.suggestion], [4, 1, null]);
  assert.deepStrictEqual([by['curl-upload'].hits, by['curl-upload'].suggestion], [2, null]);
  assert.ok(!by.keychain, 'rules in ask or block mode are not listed');
  const before = fs.readFileSync(path.join(home, '.config', 'mac-yolo', 'credential-guard.json'), 'utf8');
  const text = G.formatPromotion(report).join('\n');
  assert.deepStrictEqual(G.doctor(ctx).promotion, report, 'doctor --json carries the same report');
  assert.match(text, /net-oneliner .*would have blocked 4x, 0 overrides {2}-> switch to block/);
  assert.strictEqual(fs.readFileSync(path.join(home, '.config', 'mac-yolo', 'credential-guard.json'), 'utf8'), before, 'modes are never changed');
});

test('log mode: the log line says the call ran', () => {
  const { ctx, home } = makeCtx();
  cfg(home, { rules: { keychain: 'log' } });
  assert.strictEqual(hook(ctx, CMD).exitCode, 0);
  const row = logRows(home)[0];
  assert.strictEqual(row.mode, 'log');
  assert.strictEqual(row.ran, true);
});

test('policyDigest is on every log line, is stable, and changes with the modes', () => {
  const a = makeCtx();
  cfg(a.home, { rules: { keychain: 'ask' } });
  hook(a.ctx, CMD);
  hook(a.ctx, 'security dump-keychain');
  const rows = logRows(a.home);
  assert.ok(rows.length >= 2);
  for (const r of rows) assert.match(r.policyDigest, /^[0-9a-f]{12}$/);
  assert.strictEqual(new Set(rows.map((r) => r.policyDigest)).size, 1, 'same config, same digest');
  const b = makeCtx();
  cfg(b.home, { rules: { keychain: 'ask' } });
  hook(b.ctx, CMD);
  assert.strictEqual(logRows(b.home)[0].policyDigest, rows[0].policyDigest, 'stable across homes');
  const c = makeCtx();
  cfg(c.home, { rules: { keychain: 'block' } });
  hook(c.ctx, CMD);
  assert.notStrictEqual(logRows(c.home)[0].policyDigest, rows[0].policyDigest);
  const text = JSON.stringify(rows);
  // The log row carries the program and subcommand only, never an argument value such as the service name.
  assert.ok(!text.includes('my-secret-service-name'), 'no argument value in the log');
  assert.ok(rows.some((r) => r.command === ['sec', 'urity find-generic-password'].join('')), 'the shape is logged');
  assert.ok(rows.every((r) => typeof r.why === 'string'), 'every row has a plain sentence');
});

test('an agent cannot run approve or deny', () => {
  const { ctx } = makeCtx();
  const r = G.evaluate({ tool_name: 'Bash', tool_input: { command: `${['mac-yolo', 'credential', 'guard'].join('-')} approve ${'a'.repeat(64)}` } }, ctx);
  assert.strictEqual(r.deny, true);
  assert.strictEqual(r.rule, 'guard-config');
});
