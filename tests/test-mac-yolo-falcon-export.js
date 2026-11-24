'use strict';

// Tests for tools/mac-yolo-falcon-export.js with a fake HTTP sender and a temporary HOME.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const F = require('../tools/mac-yolo-falcon-export');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'falcon-export-'));
const log = path.join(home, 'guard.jsonl');
const cursor = path.join(home, 'state', 'falcon-export.cursor');
const TOKEN = 'tok-SECRET-123456';
let count = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const rows = (n, extra = {}) => Array.from({ length: n }, (_, i) => ({
  at: new Date(Date.UTC(2026, 10, 19, 10, 0, 0) + i * 1000).toISOString(),
  agent: 'claude', tool: 'Bash', rule: 'keychain', technique: 'T1555.001', mode: 'block', denied: true, parents: ['node'], ...extra,
}));
const write = (rs) => fs.writeFileSync(log, rs.map((r) => `${JSON.stringify(r)}\n`).join(''));
const reset = () => { fs.rmSync(path.join(home, 'state'), { recursive: true, force: true }); };
const env = { MAC_YOLO_FALCON_URL: 'https://ingest.example.com/', MAC_YOLO_FALCON_TOKEN: TOKEN };
const deps = (send) => ({ home, cursorFile: cursor, host: 'testhost', send });

test('body shape matches the LogScale structured ingest docs', async () => {
  reset(); write(rows(2));
  const calls = [];
  const r = await F.run(['--log', log], env, deps(async (url, token, body) => { calls.push({ url, token, body }); return 204; }));
  assert.strictEqual(r.code, 0);
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].url, 'https://ingest.example.com/api/v1/ingest/humio-structured');
  assert.strictEqual(calls[0].token, TOKEN);
  const [group] = calls[0].body;
  assert.deepStrictEqual(group.tags, { source: 'mac-yolo-safeguards', host: 'testhost' });
  assert.strictEqual(group.events.length, 2);
  const ev = group.events[0];
  assert.strictEqual(ev.timestamp, '2026-11-19T10:00:00.000Z');
  assert.strictEqual(ev.attributes.rule, 'keychain');
  assert.strictEqual(ev.attributes.ruleId, 'keychain');
  assert.deepStrictEqual(ev.attributes.attackTechniqueIds, ['T1555.001']);
  assert.strictEqual(ev.attributes.agent, 'claude');
  assert.strictEqual(ev.attributes.denied, true);
  assert.ok(ev.attributes.reason);
});

test('batches at 500 events per request', async () => {
  reset(); write(rows(1203));
  const sizes = [];
  const r = await F.run(['--log', log], env, deps(async (u, t, body) => { sizes.push(body[0].events.length); return 200; }));
  assert.strictEqual(r.code, 0);
  assert.deepStrictEqual(sizes, [500, 500, 203]);
});

test('cursor advances only after a 2xx; non-2xx exits non-zero with the status code only', async () => {
  reset(); write(rows(3));
  let r = await F.run(['--log', log], env, deps(async () => 503));
  assert.strictEqual(r.code, 1);
  assert.strictEqual(r.stderr.trim(), 'mac-yolo-falcon-export: HTTP 503');
  assert.ok(!fs.existsSync(cursor));
  r = await F.run(['--log', log], env, deps(async () => 200));
  assert.strictEqual(r.code, 0);
  assert.strictEqual(fs.readFileSync(cursor, 'utf8').trim(), '2026-11-19T10:00:02.000Z');
  // Next run sends only newer rows.
  let n = 0;
  write(rows(3).concat(rows(1, { at: '2026-11-19T11:00:00.000Z' })));
  await F.run(['--log', log], env, deps(async (u, t, body) => { n += body[0].events.length; return 200; }));
  assert.strictEqual(n, 1);
});

test('a failure mid-way keeps the cursor at the last good batch', async () => {
  reset(); write(rows(700));
  let calls = 0;
  const r = await F.run(['--log', log], env, deps(async () => (++calls === 1 ? 200 : 500)));
  assert.strictEqual(r.code, 1);
  assert.strictEqual(fs.readFileSync(cursor, 'utf8').trim(), rows(500)[499].at);
});

test('--dry-run and a missing URL send nothing and leave the cursor alone', async () => {
  reset(); write(rows(2));
  const send = async () => { throw new Error('must not send'); };
  let r = await F.run(['--log', log, '--dry-run'], env, deps(send));
  assert.strictEqual(r.code, 0);
  assert.strictEqual(JSON.parse(r.stdout)[0][0].events.length, 2);
  r = await F.run(['--log', log], { MAC_YOLO_FALCON_TOKEN: TOKEN }, deps(send));
  assert.strictEqual(r.code, 0);
  assert.strictEqual(JSON.parse(r.stdout)[0][0].events.length, 2);
  assert.ok(!fs.existsSync(cursor));
});

test('--since overrides the cursor', async () => {
  reset(); write(rows(5));
  const r = await F.run(['--log', log, '--since', '2026-11-19T10:00:03Z', '--dry-run'], env, deps());
  assert.strictEqual(JSON.parse(r.stdout)[0][0].events.length, 1);
});

test('token never appears in stdout, stderr or the dry-run body', async () => {
  reset(); write(rows(2, { token: TOKEN, secret: TOKEN }));
  for (const argv of [['--log', log, '--dry-run'], ['--log', log]]) {
    for (const send of [async () => 200, async () => 401, async () => { throw new Error(`boom ${TOKEN}`); }]) {
      const r = await F.run(argv, env, deps(send));
      assert.ok(!r.stdout.includes(TOKEN) && !r.stderr.includes(TOKEN));
    }
  }
  const r = await F.run(['--log', log, '--token', TOKEN], env, deps());
  assert.strictEqual(r.code, 2);
  assert.ok(!r.stderr.includes(TOKEN));
});

test('sensitive fields are stripped and home paths are scrubbed', async () => {
  reset();
  write(rows(1, { command: 'cat ~/.ssh/id_rsa', args: ['x'], env: { A: 'b' }, token: 'T', secret: 'S', Command: 'c', reason: `reads ${home}/x`, policyVersion: '3' }));
  const r = await F.run(['--log', log, '--dry-run'], env, deps());
  const ev = JSON.parse(r.stdout)[0][0].events[0];
  const text = JSON.stringify(ev);
  for (const k of ['command', 'args', 'env', 'token', 'secret', 'parents']) assert.ok(!(k in ev.attributes), k);
  assert.ok(!text.includes('id_rsa') && !text.includes(home));
  assert.strictEqual(ev.attributes.reason, 'reads ~/x');
  assert.strictEqual(ev.attributes.policyVersion, '3');
});

test('bad rows are skipped', async () => {
  reset();
  fs.writeFileSync(log, `not json\n{"at":"nope"}\n${JSON.stringify(rows(1)[0])}\n`);
  const r = await F.run(['--log', log, '--dry-run'], env, deps());
  assert.strictEqual(JSON.parse(r.stdout)[0][0].events.length, 1);
});

(async () => {
  for (const [name, fn] of tests) {
    try { await fn(); count += 1; } catch (e) { console.error(`FAIL: ${name}\n${e.stack}`); process.exitCode = 1; }
  }
  fs.rmSync(home, { recursive: true, force: true });
  console.log(`mac-yolo-falcon-export: ${count}/${tests.length} tests passed`);
})();
