'use strict';

// Installed-copy smoke test for tools/mac-yolo-credential-guard.js.
//
// The other tests load the guard from this checkout. The agents run a different file: `install` copies the guard
// to ~/.local/share/mac-yolo-safeguards/ and writes a hook command that points there. If that copy cannot run on
// its own (for example a later change makes it require a file next to it, such as ./lib/x.js, that `install` does
// not copy), the hook exits 1. Claude Code, Codex and Cursor treat a hook that exits 1 as a hook error, not a deny,
// so the call goes ahead and nothing tells the user the guard is gone.
//
// This test installs into a temporary HOME, then runs the exact hook command from the written settings file, from
// a folder outside this checkout, and checks that the copy still blocks and still allows. The idea comes from
// vllm-project/vllm-gr, which builds its wheel and runs a smoke test against the installed package instead of the
// source tree (tools/packaging/run_wheel_smoke_test.sh).
//
// Nothing here reads a real keychain or browser profile, and nothing outside the temporary folder is changed.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'mac-yolo-credential-guard.js');

const BASE = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'mycg-installed-')));
const home = path.join(BASE, 'home');
const elsewhere = path.join(BASE, 'elsewhere');
fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
fs.mkdirSync(elsewhere, { recursive: true });
const env = { PATH: '/usr/bin:/bin', HOME: home };

const passed = [];
function req(id, fn) {
  fn();
  passed.push(id);
  console.log(`ok ${id}`);
}

function hookCommand() {
  const settings = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'));
  const entry = (settings.hooks.PreToolUse || []).flatMap((m) => m.hooks || [])
    .find((h) => /mac-yolo-credential-guard/.test(h.command || ''));
  assert.ok(entry, 'install wrote no PreToolUse hook for the guard');
  return entry.command;
}

// Runs the hook the way the agent does: the settings command through a shell, the payload on stdin.
function runInstalledHook(call) {
  const payload = JSON.stringify({ hook_event_name: 'PreToolUse', cwd: elsewhere, ...call });
  return spawnSync('/bin/sh', ['-c', hookCommand()], { input: payload, encoding: 'utf8', cwd: elsewhere, env });
}

try {
  req('INSTALLED-01 install writes a hook that points at the installed copy, not this checkout', () => {
    const r = spawnSync(process.execPath, [TOOL, 'install', '--agent', 'claude'], { encoding: 'utf8', cwd: elsewhere, env });
    assert.strictEqual(r.status, 0, `install failed: ${r.stderr}`);
    const cmd = hookCommand();
    assert.ok(cmd.includes(path.join(home, '.local', 'share', 'mac-yolo-safeguards')), `hook points elsewhere: ${cmd}`);
    assert.ok(!cmd.includes(ROOT), `hook points into the checkout: ${cmd}`);
  });

  req('INSTALLED-02 the installed copy loads nothing from next to it', () => {
    const dir = path.join(home, '.local', 'share', 'mac-yolo-safeguards');
    const src = fs.readFileSync(path.join(dir, 'mac-yolo-credential-guard.js'), 'utf8');
    // Only Node built-ins may be required: `install` copies this one file and nothing else. Comments and strings
    // that mention require('/x') are not code, so only `const|let|var ... = require(...)` statements count.
    const local = [...src.matchAll(/^\s*(?:const|let|var)\s[^\n]*?=\s*require\(\s*['"]([^'"]+)['"]\s*\)/gm)].map((m) => m[1])
      .filter((name) => name.startsWith('.') || name.startsWith('/'));
    assert.deepStrictEqual(local, [], `installed guard requires files install does not copy: ${local.join(', ')}`);
  });

  req('INSTALLED-03 the installed hook blocks a keychain read with exit 2', () => {
    const r = runInstalledHook({ tool_name: 'Bash', tool_input: { command: 'security find-generic-password -s "Chrome Safe Storage" -w' } });
    assert.strictEqual(r.status, 2, `expected exit 2 (deny), got ${r.status}: ${r.stderr}`);
    assert.match(r.stderr, /rule keychain/);
  });

  req('INSTALLED-04 the installed hook blocks a browser login file read through the Read tool', () => {
    const file = path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Login Data');
    const r = runInstalledHook({ tool_name: 'Read', tool_input: { file_path: file } });
    assert.strictEqual(r.status, 2, `expected exit 2 (deny), got ${r.status}: ${r.stderr}`);
  });

  req('INSTALLED-05 the installed hook allows ordinary work with exit 0', () => {
    for (const command of ['npm test', 'git status', 'grep -r "security find-generic-password" docs/']) {
      const r = runInstalledHook({ tool_name: 'Bash', tool_input: { command } });
      assert.strictEqual(r.status, 0, `expected exit 0 for ${command}, got ${r.status}: ${r.stderr}`);
    }
  });
} finally {
  fs.rmSync(BASE, { recursive: true, force: true });
}

console.log(`\n${passed.length}/5 installed-copy checks pass`);
