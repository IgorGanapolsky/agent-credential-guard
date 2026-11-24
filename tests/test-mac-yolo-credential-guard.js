'use strict';

// Tests for tools/mac-yolo-credential-guard.js. Every test uses a temporary HOME and fake runners: nothing here
// calls `security`, `xattr` or `launchctl`, or opens a real keychain or browser profile.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'mac-yolo-credential-guard.js');
const FIXTURES = path.join(__dirname, 'fixtures', 'credential-guard');
const G = require(TOOL);

const BASE = fs.mkdtempSync(path.join(os.tmpdir(), 'mycg-test-'));
const REAL_HOME = os.homedir();
const REAL_LOG = path.join(REAL_HOME, 'Library', 'Logs', 'mac-yolo', 'credential-guard.jsonl');
const realLogSize = () => { try { return fs.statSync(REAL_LOG).size; } catch { return -1; } };
const REAL_LOG_BEFORE = realLogSize();

let n = 0;
function makeCtx(opts = {}) {
  const dir = path.join(BASE, `case-${n += 1}`);
  const home = path.join(dir, 'home');
  const tmp = path.join(dir, 'tmp');
  const bin = path.join(dir, 'bin');
  const apps = path.join(dir, 'Applications');
  for (const d of [home, tmp, bin, apps]) fs.mkdirSync(d, { recursive: true });
  const calls = [];
  return {
    dir,
    calls,
    ctx: {
      home,
      env: opts.env || {},
      tmpRoots: [tmp],
      pathDirs: [bin],
      appDirs: [apps],
      logDir: path.join(home, 'Library', 'Logs', 'mac-yolo'),
      nodePath: process.execPath,
      run: (cmd, args) => {
        calls.push([cmd, ...args]);
        return (opts.run && opts.run(cmd, args)) || { status: 1, stdout: '', stderr: '' };
      },
      now: () => new Date('2026-11-19T15:00:00Z'),
    },
  };
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const denied = (ctx, payload) => G.evaluate(payload, ctx);

function expectRule(ctx, payload, rule) {
  const v = denied(ctx, payload);
  assert.strictEqual(v.deny, true, `expected deny (${rule}) for ${JSON.stringify(payload)}`);
  assert.strictEqual(v.rule, rule, `expected rule ${rule}, got ${v.rule} for ${JSON.stringify(payload)}`);
}
function expectAllow(ctx, payload) {
  const v = denied(ctx, payload);
  assert.strictEqual(v.deny, false, `expected allow for ${JSON.stringify(payload)}, got ${v.rule}`);
}

function runCli(args, { home, input = '', env = {} }) {
  const r = spawnSync(process.execPath, [TOOL, ...args], {
    input, encoding: 'utf8', env: { PATH: '/usr/bin:/bin', HOME: home, ...env },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const passed = [];
function req(id, fn) {
  fn();
  passed.push(id);
  console.log(`${id} pass`);
}

try {
  req('REQ-01', () => {
    const { ctx } = makeCtx();
    const reads = [
      'security find-generic-password -s "Chrome Safe Storage" -w',
      '/usr/bin/security find-generic-password -wa Chrome',
      'security dump-keychain -d login.keychain',
      'security find-internet-password -s github.com -g',
      'security export -k login.keychain -t identities -f pkcs12 -o /tmp/x.p12',
      'security -v find-generic-password -s x',
      'python3 -c "import os; os.system(\'security find-generic-password -s x -w\')"',
      'python3 -c "import subprocess; subprocess.run([\\"security\\",\\"find-generic-password\\",\\"-w\\"])"',
      'cd /tmp && security dump-keychain > /tmp/k.txt',
      'sec""urity find-generic-password -s x -w',
      "s'ecurity' dump-keychain",
      's\\ecurity dump-keychain',
      'echo find-generic-password -ws x | security -i',
      'security -qi < /tmp/cmds',
      'security find-key -t private',
      'sudo security dump-keychain',
      'env FOO=1 security find-generic-password -s x',
      'echo x | xargs security find-generic-password -s',
      'bash -lc "security dump-keychain"',
      'python3 -c "import keyring; print(keyring.get_password(\'a\',\'b\'))"',
      'keyring get service user',
      '(security dump-keychain)',
      '{ security dump-keychain; }',
      'if true; then security find-generic-password -s "Chrome Safe Storage" -w; fi',
      'x=`security find-generic-password -s x -w`',
      'echo `security dump-keychain`',
      'sec``urity dump-keychain',
      'echo $(security dump-keychain)',
      'sudo -u root security dump-keychain',
      'timeout 5 security dump-keychain',
      'eval security dump-keychain',
      'sudo -u root security -i',
    ];
    for (const c of reads) expectRule(ctx, bash(c), 'keychain');
    expectRule(ctx, { tool_name: 'Read', tool_input: { file_path: `${ctx.home}/Library/Keychains/login.keychain-db` } }, 'keychain-file');
    expectRule(ctx, bash('cp ~/Library/Keychains/login.keychain-db /tmp/k'), 'keychain-file');
    expectRule(ctx, { tool_name: 'Bash', tool_input: { command: ['security', 'find-generic-password', '-w'] } }, 'keychain');

    const r = runCli(['hook', '--agent', 'claude'], {
      home: ctx.home, input: fs.readFileSync(path.join(FIXTURES, 'claude-chrome-safe-storage.json'), 'utf8'),
    });
    assert.strictEqual(r.status, 2, r.stderr);
    assert.match(r.stderr, /reads the macOS keychain\. Instead: /);
    assert.strictEqual(r.stdout, '');
  });

  req('REQ-02', () => {
    const { ctx } = makeCtx();
    const chrome = 'Library/Application Support/Google/Chrome/Default';
    const cmds = [
      `cp "$HOME/${chrome}/Cookies" /tmp/x_cookies.db`,
      `cp ~/${chrome.replace(/ /g, '\\ ')}/Login\\ Data /tmp/chrome_logins.db`,
      `sqlite3 "${ctx.home}/${chrome}/Login Data" "select * from logins"`,
      `cat "\${HOME}/Library/Application Support/Google/Chrome/Local State"`,
      'cp -R "$HOME/Library/Application Support/Google/Chrome" /private/tmp/chrome-prof',
      'ditto ~/Library/Application\\ Support/BraveSoftware/Brave-Browser /tmp/b',
      'tar czf /tmp/e.tgz "$HOME/Library/Application Support/Microsoft Edge/Default/Cookies"',
      'cp "$HOME/Library/Application Support/Arc/User Data/Default/Login Data" /tmp/a',
      'cp "$HOME/Library/Application Support/Chromium/Default/Cookies" /tmp/c',
      'cp "$HOME/Library/Application Support/Google/Chrome Canary/Default/Cookies" /tmp/c',
      'cp ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies /tmp/s',
      'cp ~/Library/Cookies/Cookies.binarycookies /tmp/s',
      'cp "$HOME/Library/Application Support/Firefox/Profiles/abc.default/logins.json" /tmp/f',
      `python3 -c "import shutil,os; shutil.copy(os.path.expanduser('~/${chrome}/Cookies'),'/tmp/c')"`,
      `cp ~/${chrome}/Coo""kies /tmp/c`,
    ];
    for (const c of cmds) expectRule(ctx, bash(c), 'browser-store');
    expectRule(ctx, { tool_name: 'Read', tool_input: { file_path: `${ctx.home}/${chrome}/Login Data` } }, 'browser-store');
    expectRule(ctx, { ...bash('cp Cookies /tmp/c'), cwd: `${ctx.home}/${chrome}` }, 'browser-store');
    expectRule(ctx, { ...bash('python3 dump.py Web\\ Data'), cwd: `${ctx.home}/${chrome}` }, 'browser-store');
    expectRule(ctx, bash(`cp "$HOME/${chrome}/Web Data" /tmp/w`), 'browser-store');
    expectAllow(ctx, { ...bash('git status'), cwd: `${ctx.home}/${chrome}` });
    expectRule(ctx, { tool_name: 'Read', tool_input: { file_path: `~/${chrome}/Cookies` } }, 'browser-store');
    expectRule(ctx, { tool_name: 'mcp__fs__read', tool_input: { path: `${ctx.home}/${chrome}/Cookies` } }, 'browser-store');
    expectRule(ctx, { tool_name: 'Grep', tool_input: { pattern: 'x', path: `${ctx.home}/Library/Application Support/Firefox/Profiles/a/cookies.sqlite` } }, 'browser-store');
    for (const lib of ['browser_cookie3', 'pycookiecheat', 'rookiepy']) {
      expectRule(ctx, bash(`python3 -c "import ${lib}; print(${lib}.chrome())"`), 'cookie-library');
    }
    // Content that only mentions a store is fine: writing docs about the rule must work.
    expectAllow(ctx, { tool_name: 'Write', tool_input: { file_path: '/tmp/doc.md', content: `never cp ~/${chrome}/Cookies` } });
    expectAllow(ctx, { tool_name: 'Read', tool_input: { file_path: '/proj/src/login.keychain.ts' } });
    expectAllow(ctx, { tool_name: 'Glob', tool_input: { pattern: '**/*.keychain-db' } });
    expectAllow(ctx, { tool_name: 'Grep', tool_input: { pattern: 'Cookies.binarycookies', path: '/proj' } });
    expectAllow(ctx, { tool_name: 'Read', tool_input: { file_path: '/proj/tests/fixtures/Library/Cookies/Cookies.binarycookies' } });
    // Partial paths, globs, symlinks and variables.
    for (const c of [
      'ln -s ~/Library/Application\\ Support/Google/Chrome /tmp/c',
      'cd ~/Library/Application\\ Support/Google && cp Chrome/Default/Cookies /tmp',
      'cp ~/Library/Application*/Google/Chrome/Default/Cookies /tmp/',
      'cp ~/Library/Application\\ Support/Google/*/Default/Cookies /tmp/',
      'mv ~/Library/Application\\ Support/Google/Chrome /tmp/x',
      'D=~/Library/Application\\ Support/Google; cp "$D/Chrome/Default/Cookies" /tmp',
    ]) expectRule(ctx, bash(c), 'browser-store');
    expectRule(ctx, { ...bash('cp Chrome/Default/Cookies /tmp'), cwd: `${ctx.home}/Library/Application Support/Google` }, 'browser-store');
    expectRule(ctx, bash('cd ~/Library && cp Keychains/login.keychain-db /tmp/k'), 'keychain-file');
    expectRule(ctx, { ...bash('cp login.keychain-db /tmp/k'), cwd: `${ctx.home}/Library/Keychains` }, 'keychain-file');
    expectAllow(ctx, bash('ls "$HOME/Library/Application Support"'));
    expectAllow(ctx, bash('open -a "Google Chrome" https://example.com'));
  });

  req('REQ-03', () => {
    const { ctx } = makeCtx();
    for (const c of [
      'xattr -d com.apple.quarantine /Applications/screenpipe.app',
      'xattr -dr com.apple.quarantine ~/Downloads/x.app',
      'sudo xattr -r -d com.apple.quarantine /opt/x',
      'xattr -c /Applications/x.app',
      'xattr -cr /Applications/x.app',
      '(xattr -cr /Applications/x.app)',
      'sudo -u root xattr -d com.apple.quarantine /Applications/x.app',
      'curl -L x | tar x && /usr/bin/xattr -d com.apple.quarantine ./bin',
    ]) expectRule(ctx, bash(c), 'quarantine');
    expectAllow(ctx, bash('xattr -l /Applications/x.app'));
    expectAllow(ctx, bash('xattr -w com.apple.quarantine "0081;0;Safari;" /tmp/x'));
    expectAllow(ctx, bash('xattr -p com.apple.quarantine /tmp/x'));
  });

  req('REQ-04', () => {
    const { ctx } = makeCtx();
    for (const c of [
      'launchctl setenv ALPACA_API_KEY abc',
      'launchctl setenv EDITOR vim OPENAI_API_KEY sk-x',
      'launchctl setenv github_token x',
      'launchctl setenv DB_PASSWORD x',
      'launchctl config user setenv SECRET_THING x',
      'launchctl setenv GH_PAT x',
      'sudo launchctl setenv PAT x',
      'sudo -u x launchctl setenv TOKEN v',
    ]) expectRule(ctx, bash(c), 'launchctl-secret');
    expectAllow(ctx, bash('launchctl setenv EDITOR vim'));
    expectAllow(ctx, bash('launchctl setenv SSH_AUTH_SOCK /tmp/agent.sock'));
    expectAllow(ctx, bash('launchctl getenv PATH'));
  });

  req('REQ-05', () => {
    const { ctx } = makeCtx();
    for (const c of ['git status', 'ls ~/Library', 'grep -r find-generic-password src', 'npm test', 'node tools/x.js --json',
      'ls src/security', 'cd packages/security && npm test', 'git add lib/security; git commit -m wip', 'npm run security',
      'git commit -m "docs: block security find-generic-password and dump-keychain"', 'rg "security find-generic-password" .',
      'gh pr create --body "denies security export"', 'echo security export', 'git commit -m "explain xattr -c and launchctl setenv API_KEY"',
      'tail -f "$HOME/Library/Application Support/Google/Chrome/chrome_debug.log"',
      'open "$HOME/Library/Application Support/Google/Chrome"',
      'CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node run.js',
      'node run.js --executable "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"']) {
      expectAllow(ctx, bash(c));
    }
    const deny = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'security dump-keychain' } });
    for (const agent of ['claude', 'codex']) {
      const r = runCli(['hook', '--agent', agent], { home: ctx.home, input: deny });
      assert.strictEqual(r.status, 2);
      assert.match(r.stderr, /^mac-yolo credential guard: blocked because/);
    }
    // Codex can send its shell command as an argv array.
    const codexArgv = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: ['bash', '-lc', 'security dump-keychain'] } });
    assert.strictEqual(runCli(['hook', '--agent', 'codex'], { home: ctx.home, input: codexArgv }).status, 2);

    const cursorShell = JSON.stringify({ hook_event_name: 'beforeShellExecution', command: 'xattr -d com.apple.quarantine x', cwd: '/tmp' });
    let r = runCli(['hook', '--agent', 'cursor'], { home: ctx.home, input: cursorShell });
    assert.strictEqual(r.status, 2);
    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.permission, 'deny');
    assert.match(out.user_message, /quarantine/);
    assert.strictEqual(out.agent_message, out.user_message);

    const cursorRead = JSON.stringify({ hook_event_name: 'beforeReadFile', file_path: `${ctx.home}/Library/Application Support/Google/Chrome/Default/Login Data` });
    r = runCli(['hook'], { home: ctx.home, input: cursorRead }); // no --agent: detected from the event name
    assert.strictEqual(r.status, 2);
    assert.strictEqual(JSON.parse(r.stdout).permission, 'deny');

    r = runCli(['hook', '--agent', 'cursor'], { home: ctx.home, input: JSON.stringify({ hook_event_name: 'beforeShellExecution', command: 'ls' }) });
    assert.strictEqual(r.status, 0);
    assert.deepStrictEqual(JSON.parse(r.stdout), { permission: 'allow' });

    r = runCli(['hook', '--agent', 'claude'], { home: ctx.home, input: JSON.stringify(bash('git status')) });
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout + r.stderr, '');

    r = runCli(['hook', '--agent', 'claude'], { home: ctx.home, input: 'null' });
    assert.strictEqual(r.status, 0, r.stderr);
    r = runCli(['hook', '--agent', 'claude'], { home: ctx.home, input: '{not json' });
    assert.strictEqual(r.status, 0);
    const log = fs.readFileSync(path.join(ctx.home, 'Library', 'Logs', 'mac-yolo', 'credential-guard.jsonl'), 'utf8');
    assert.match(log, /"rule":"parse_error"/);
    // The deny log holds the action's shape (program, subcommand, flag names), never argument values.
    assert.match(log, /"summary":"security dump-keychain"/);
    assert.match(log, /"summary":"xattr -d …"/);
    // The log holds the redacted command and a plain sentence.
    assert.match(log, /"why":"tried to remove the macOS safety flag/);
    assert.match(log, /"command":"xattr"/);
    assert.match(log, /"rule":"keychain"/);
  });

  req('REQ-06', () => {
    const { ctx } = makeCtx();
    const claudeFile = path.join(ctx.home, '.claude', 'settings.json');
    const codexFile = path.join(ctx.home, '.codex', 'hooks.json');
    const cursorFile = path.join(ctx.home, '.cursor', 'hooks.json');
    write(claudeFile, JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'other-hook' }] }], Stop: [{ hooks: [{ type: 'command', command: 'stop-hook' }] }] } }));
    write(codexFile, JSON.stringify({ hooks: {} }));
    write(cursorFile, JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: 'cursor-other' }] } }));

    const res = G.install(ctx, 'all');
    assert.strictEqual(res.changed.length, 3);
    assert.ok(fs.existsSync(path.join(ctx.home, '.local', 'share', 'mac-yolo-safeguards', 'mac-yolo-credential-guard.js')));
    const claude = JSON.parse(fs.readFileSync(claudeFile, 'utf8'));
    assert.strictEqual(claude.model, 'x');
    assert.strictEqual(claude.hooks.PreToolUse.length, 2);
    assert.match(JSON.stringify(claude.hooks.PreToolUse), /other-hook/);
    assert.match(JSON.stringify(claude.hooks.Stop), /stop-hook/);
    const ours = claude.hooks.PreToolUse[0].hooks[0].command;
    assert.strictEqual(ours, `${JSON.stringify(process.execPath)} ${JSON.stringify(path.join(ctx.home, '.local', 'share', 'mac-yolo-safeguards', 'mac-yolo-credential-guard.js'))} hook --agent claude`);
    assert.doesNotMatch(ours, /\s-[ce]\s/);
    const codex = JSON.parse(fs.readFileSync(codexFile, 'utf8'));
    assert.strictEqual(codex.hooks.PreToolUse.length, 1);
    assert.match(codex.hooks.PreToolUse[0].hooks[0].command, /hook --agent codex$/);
    const cursor = JSON.parse(fs.readFileSync(cursorFile, 'utf8'));
    assert.strictEqual(cursor.hooks.beforeShellExecution.length, 2);
    assert.strictEqual(cursor.hooks.beforeReadFile.length, 1);
    assert.match(cursor.hooks.beforeReadFile[0].command, /hook --agent cursor$/);
    for (const f of [claudeFile, codexFile, cursorFile]) {
      assert.strictEqual(fs.readdirSync(path.dirname(f)).filter((x) => x.includes('.mac-yolo-backup-')).length, 1, `backup for ${f}`);
    }
    for (const a of ['claude', 'codex', 'cursor']) assert.strictEqual(G.hookInstalled(ctx, a), true);

    const snapshot = [claudeFile, codexFile, cursorFile].map((f) => fs.readFileSync(f, 'utf8'));
    assert.deepStrictEqual(G.install(ctx, 'all').changed, []);
    assert.deepStrictEqual([claudeFile, codexFile, cursorFile].map((f) => fs.readFileSync(f, 'utf8')), snapshot);

    G.uninstall(ctx, 'all');
    const after = JSON.parse(fs.readFileSync(claudeFile, 'utf8'));
    assert.strictEqual(after.hooks.PreToolUse.length, 1);
    assert.match(JSON.stringify(after), /other-hook/);
    assert.doesNotMatch(JSON.stringify(after), /mac-yolo-credential-guard/);
    assert.doesNotMatch(fs.readFileSync(cursorFile, 'utf8'), /mac-yolo-credential-guard/);
    assert.match(fs.readFileSync(cursorFile, 'utf8'), /cursor-other/);
    assert.throws(() => G.install(ctx, 'notanagent'), /unknown agent/);

    // A dotfiles symlink stays a symlink, and the real file keeps its mode.
    const dot = path.join(ctx.home, 'dotfiles', 'codex-hooks.json');
    write(dot, JSON.stringify({ hooks: {} }));
    fs.chmodSync(dot, 0o644);
    fs.rmSync(codexFile);
    fs.symlinkSync(dot, codexFile);
    G.install(ctx, 'codex');
    assert.ok(fs.lstatSync(codexFile).isSymbolicLink());
    assert.match(fs.readFileSync(dot, 'utf8'), /hook --agent codex/);
    assert.strictEqual(fs.statSync(dot).mode & 0o777, 0o644);

    // Codex trusts hooks per position, so the guard goes last and existing hooks keep their slots.
    write(dot, JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'other-hook' }] }] } }));
    G.install(ctx, 'codex');
    const cx = JSON.parse(fs.readFileSync(dot, 'utf8')).hooks.PreToolUse;
    assert.strictEqual(cx[0].hooks[0].command, 'other-hook');
    assert.match(cx[1].hooks[0].command, /hook --agent codex$/);
    const tomlFile = path.join(ctx.home, '.codex', 'config.toml');
    write(tomlFile, 'model = "x"\n');
    assert.strictEqual(G.doctor(ctx).findings.find((f) => f.kind === 'codex-trust').severity, 'warn');
    write(tomlFile, `[hooks.state."${codexFile}:pre_tool_use:1:0"]\nenabled = false\ntrusted_hash = "h"\n`);
    assert.strictEqual(G.doctor(ctx).findings.find((f) => f.kind === 'codex-trust').severity, 'high');
    write(tomlFile, `[hooks.state."${codexFile}:pre_tool_use:1:0"]\nenabled = true\ntrusted_hash = "h"\n`);
    assert.strictEqual(G.doctor(ctx).findings.find((f) => f.kind === 'codex-trust'), undefined);
    fs.rmSync(tomlFile);

    // A hook whose node binary is gone blocks nothing, so it does not count as installed.
    const gone = { ...ctx, nodePath: path.join(ctx.home, 'old-node', 'bin', 'node') };
    G.install(gone, 'claude');
    assert.strictEqual(G.hookInstalled(ctx, 'claude'), false);
    const broken = G.doctor(ctx).findings.find((f) => f.kind === 'hook-missing' && f.fix.agent === 'claude');
    assert.strictEqual(broken.severity, 'high');
    assert.match(broken.title, /broken/);
  });

  // A fixture HOME seeded with one of everything the doctor looks for.
  function seededHome() {
    const env = makeCtx({
      env: { MY_SERVICE_TOKEN: 'x', PATH: '/usr/bin' },
      run: (cmd, args) => {
        if (cmd === '/bin/launchctl' && args[0] === 'getenv' && ['TRADING_API_KEY', 'MY_SERVICE_TOKEN'].includes(args[1])) {
          return { status: 0, stdout: 'super-secret-value-123\n', stderr: '' };
        }
        if (cmd === '/bin/launchctl' && args[0] === 'unsetenv') return { status: 0, stdout: '', stderr: '' };
        if (cmd === '/usr/bin/xattr') return { status: 0, stdout: 'com.apple.metadata:kMDItemWhereFroms\n', stderr: '' };
        return null;
      },
    });
    const { ctx } = env;
    const tmp = ctx.tmpRoots[0];
    const sqlite = Buffer.concat([Buffer.from('SQLite format 3\0'), Buffer.alloc(84), Buffer.from('CREATE TABLE logins (origin_url VARCHAR NOT NULL)')]);
    const cookieDb = Buffer.concat([Buffer.from('SQLite format 3\0'), Buffer.alloc(84), Buffer.from('CREATE TABLE cookies (host_key TEXT)')]);
    fs.writeFileSync(path.join(tmp, 'login-data-copy.db'), sqlite);
    write(path.join(tmp, 'x_cookies.json'), '[{"domain":".x.com","name":"auth_token","value":"v"}]');
    // Not credential stores: names that only look like one, and a live automation profile.
    write(path.join(tmp, 'fortune-cookies.txt'), 'you will ship today');
    write(path.join(tmp, 'test_cookies.json'), '{"accept": true}');
    fs.mkdirSync(path.join(tmp, 'playwright_chromiumdev_profile-abc', 'Default'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'playwright_chromiumdev_profile-abc', 'Default', 'Cookies'), cookieDb);
    write(path.join(tmp, 'claude-1', 'proj', 'sess', 'scratch', 'data.db'), '');
    fs.writeFileSync(path.join(tmp, 'claude-1', 'proj', 'sess', 'scratch', 'data.db'), sqlite);
    fs.mkdirSync(path.join(tmp, 'claude-1', 'chrome-prof-1', 'Default'), { recursive: true });
    write(path.join(tmp, 'notes.txt'), 'nothing');
    write(path.join(ctx.home, '.zshrc'), 'export PATH=$PATH\nlaunchctl setenv TRADING_API_KEY "$(cat ~/.k)"\nalias cl="claude --dangerously-skip-permissions"\n');
    write(path.join(ctx.home, '.claude', 'settings.json'), JSON.stringify({
      permissions: { defaultMode: 'bypassPermissions' }, remoteControlAtStartup: true,
      hooks: {
        PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'python3 -c "import socket; s=socket.socket()"' }] }],
        Stop: [{ hooks: [{ type: 'command', command: 'bash -e /opt/hooks/stop.sh' }, { type: 'command', command: 'node /opt/hooks/x.js' }] }],
      },
    }));
    write(path.join(ctx.home, '.codex', 'config.toml'), 'model = "x"\napproval_policy = "never"\n\n[profiles.fast]\nsandbox_mode = "danger-full-access"\n');
    write(path.join(ctx.home, '.gemini', 'antigravity-cli', 'settings.json'), JSON.stringify({ autoApproveTools: true, autoExecutionPolicy: 'always-proceed', dangerouslySkipPermissions: false }));
    write(path.join(ctx.pathDirs[0], 'grok-yolo'), '#!/bin/sh\nexec grok --always-approve "$@"\n');
    write(path.join(ctx.pathDirs[0], 'pool-yolo'), '#!/bin/sh\nexec pool acp --sandbox disabled "$@"\n');
    write(path.join(ctx.pathDirs[0], 'codex-yolo'), '#!/bin/sh\nexec codex --dangerously-bypass-approvals-and-sandbox "$@"\n');
    write(path.join(ctx.appDirs[0], 'screenpipe.app', 'Contents', 'Info.plist'), '<plist/>');
    write(path.join(ctx.pathDirs[0], 'screenpipe-mcp'), '#!/bin/sh\nexec screenpipe mcp\n'); // a script: no finding
    fs.symlinkSync(path.join(env.dir, 'missing'), path.join(ctx.pathDirs[0], 'screenpipe-cli')); // broken link: no finding
    fs.writeFileSync(path.join(ctx.pathDirs[0], 'screenpipe'), Buffer.from('cffaedfe0000', 'hex')); // a Mach-O binary
    write(path.join(ctx.pathDirs[0], 'yolo-health'), '#!/bin/sh\ncheck "grep -q \'--yolo\' x"\n# claude --yolo in a comment\n');
    return env;
  }

  req('REQ-07', () => {
    const { ctx } = seededHome();
    const report = G.doctor(ctx);
    const text = JSON.stringify(report);
    assert.doesNotMatch(text, /super-secret-value-123/, 'a secret value leaked into the report');
    const by = (kind) => report.findings.filter((f) => f.kind === kind);
    const tmpPaths = by('tmp-copy').map((f) => path.basename(f.fix.path)).sort();
    assert.deepStrictEqual(tmpPaths, ['chrome-prof-1', 'data.db', 'login-data-copy.db', 'x_cookies.json']);
    const envF = by('launchctl-env');
    assert.deepStrictEqual(envF.map((f) => f.fix.name).sort(), ['MY_SERVICE_TOKEN', 'TRADING_API_KEY']);
    assert.match(envF.find((f) => f.fix.name === 'TRADING_API_KEY').detail, /\.zshrc:2/);
    const titles = by('auto-approve').map((f) => f.title).join('\n');
    assert.match(titles, /Claude Code runs in bypassPermissions mode/);
    assert.match(titles, /Codex approval_policy = "never"/);
    assert.match(titles, /Codex \[profiles\.fast\] sandbox_mode = "danger-full-access"/);
    assert.match(titles, /Antigravity autoApproveTools is true/);
    assert.match(titles, /autoExecutionPolicy/);
    assert.match(titles, /--always-approve/);
    assert.match(titles, /--sandbox disabled/);
    assert.match(titles, /--dangerously-bypass-approvals-and-sandbox/);
    assert.match(titles, /shell startup file turns on auto-approve: --dangerously-skip-permissions/);
    assert.doesNotMatch(titles, /dangerouslySkipPermissions/); // false stays quiet
    assert.match(by('auto-approve').find((f) => /bypassPermissions/.test(f.title)).detail, /remote control on at startup; no credential hook/);
    const inline = by('inline-hook');
    assert.ok(!inline.some((f) => /errexit/.test(f.detail)));
    assert.strictEqual(inline.length, 1);
    assert.strictEqual(inline[0].severity, 'high');
    assert.match(inline[0].title, /PostToolUse hook runs an inline python3 script that opens network connections/);
    const rec = by('recorder');
    assert.deepStrictEqual(rec.map((f) => path.basename(f.fix.path)).sort(), ['screenpipe', 'screenpipe.app']);
    assert.match(rec[0].title, /downloaded with its quarantine flag stripped/);
    assert.strictEqual(rec[0].severity, 'high');
    assert.doesNotMatch(titles + JSON.stringify(by('auto-approve')), /yolo-health/, 'a grep check or comment is not a wrapper');
    assert.deepStrictEqual(by('hook-missing').map((f) => f.fix.agent).sort(), ['claude', 'codex']);
    assert.strictEqual(report.ok, false);
    assert.doesNotMatch(G.formatDoctor(report), /super-secret-value-123/);
    // Text mode: one line per finding plus header and footer.
    assert.strictEqual(G.formatDoctor(report).split('\n').length, report.findings.length + 2);

    const clean = makeCtx().ctx;
    const empty = G.doctor(clean);
    assert.deepStrictEqual(empty.findings, []);
    assert.strictEqual(empty.ok, true);
  });

  req('REQ-08', () => {
    const { ctx, calls } = seededHome();
    const report = G.doctor(ctx);
    const find = (pred) => report.findings.find(pred);
    const trash = path.join(ctx.home, '.Trash');

    const copy = find((f) => f.kind === 'tmp-copy' && /x_cookies/.test(f.fix.path));
    assert.deepStrictEqual(G.fix(ctx, copy.id, { ask: () => 'n' }), { ok: false, id: copy.id, skipped: true });
    assert.ok(fs.existsSync(copy.fix.path), 'a "n" answer must change nothing');
    assert.strictEqual(G.fix(ctx, copy.id, { ask: () => '' }).skipped, true);
    const moved = G.fix(ctx, copy.id, { ask: () => 'y' });
    assert.strictEqual(moved.ok, true);
    assert.ok(!fs.existsSync(copy.fix.path));
    assert.ok(moved.movedTo.startsWith(trash));
    assert.match(fs.readFileSync(moved.movedTo, 'utf8'), /auth_token/, 'content is still there in the Trash');

    const prof = find((f) => f.kind === 'tmp-copy' && /chrome-prof/.test(f.fix.path));
    const movedDir = G.fix(ctx, prof.id, { yes: true });
    assert.ok(fs.statSync(path.join(movedDir.movedTo, 'Default')).isDirectory());

    const envF = find((f) => f.kind === 'launchctl-env' && f.fix.name === 'TRADING_API_KEY');
    const ran = G.fix(ctx, envF.id, { yes: true });
    assert.strictEqual(ran.ok, true);
    assert.ok(calls.some((c) => c.join(' ') === '/bin/launchctl unsetenv TRADING_API_KEY'));

    const settings = path.join(ctx.home, '.claude', 'settings.json');
    const before = fs.readFileSync(settings, 'utf8');
    const bypass = find((f) => /bypassPermissions/.test(f.title));
    const r1 = G.fix(ctx, bypass.id, { yes: true });
    assert.strictEqual(fs.readFileSync(r1.backup, 'utf8'), before);
    assert.ok(r1.backup.startsWith(trash));
    const now = JSON.parse(fs.readFileSync(settings, 'utf8'));
    assert.strictEqual(now.permissions.defaultMode, 'default');
    assert.strictEqual(now.remoteControlAtStartup, true, 'other keys untouched');

    const inline = G.doctor(ctx).findings.find((f) => f.kind === 'inline-hook');
    G.fix(ctx, inline.id, { yes: true });
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(settings, 'utf8')).hooks.PostToolUse, []);

    const toml = path.join(ctx.home, '.codex', 'config.toml');
    for (const f of G.doctor(ctx).findings.filter((x) => x.title.startsWith('Codex'))) G.fix(ctx, f.id, { yes: true });
    assert.strictEqual(fs.readFileSync(toml, 'utf8'), 'model = "x"\napproval_policy = "on-request"\n\n[profiles.fast]\nsandbox_mode = "workspace-write"\n');

    const wrapper = G.doctor(ctx).findings.find((f) => /--always-approve/.test(f.title));
    const nofix = G.fix(ctx, wrapper.id, { yes: true });
    assert.strictEqual(nofix.ok, false);
    assert.match(nofix.error, /no automatic fix/);
    assert.ok(fs.existsSync(wrapper.fix.path || path.join(ctx.pathDirs[0], 'grok-yolo')));

    const recorder = G.doctor(ctx).findings.find((f) => f.kind === 'recorder' && f.fix.path.endsWith('.app'));
    const rr = G.fix(ctx, recorder.id, { yes: true });
    assert.ok(fs.existsSync(path.join(rr.movedTo, 'Contents', 'Info.plist')));

    assert.strictEqual(G.fix(ctx, 'tmp-copy:00000000', { yes: true }).ok, false);
    // Nothing the tests did reached the real Mac's guard log.
    assert.strictEqual(realLogSize(), REAL_LOG_BEFORE);
  });

  req('REQ-09', () => {
    const { ctx } = makeCtx();
    expectAllow(ctx, { ...bash('git status'), cwd: '/fake/work/repo' }); // no list file yet
    G.workFolders(ctx, 'add', '/fake/work');
    assert.deepStrictEqual(G.workFolders(ctx, 'list').folders, ['/fake/work']);
    expectRule(ctx, { ...bash('git status'), cwd: '/fake/work/repo' }, 'work-folder');
    expectRule(ctx, { ...bash('cat /fake/work/repo/src/a.js'), cwd: '/tmp' }, 'work-folder');
    expectRule(ctx, { tool_name: 'Read', tool_input: { file_path: '/fake/work/a.js' }, cwd: '/tmp' }, 'work-folder');
    expectAllow(ctx, { ...bash('git status'), cwd: '/fake/workshop' });
    expectRule(ctx, { ...bash('cat work/notes.txt'), cwd: '/fake' }, 'work-folder');
    expectRule(ctx, { ...bash('cd work && git log'), cwd: '/fake' }, 'work-folder');
    expectRule(ctx, { ...bash('git -C work status'), cwd: '/fake' }, 'work-folder');
    expectRule(ctx, { tool_name: 'Read', tool_input: { file_path: 'work/a.js' }, cwd: '/fake' }, 'work-folder');
    expectAllow(ctx, { ...bash('cat workshop/notes.txt'), cwd: '/fake' });
    const workCtx = { ...ctx, env: { MAC_YOLO_WORK_AGENT: '1' } };
    expectAllow(workCtx, { ...bash('git status'), cwd: '/fake/work/repo' });

    const list = path.join(ctx.home, '.config', 'mac-yolo', 'work-folders');
    expectRule(ctx, { tool_name: 'Write', tool_input: { file_path: list, content: '' } }, 'guard-config');
    expectRule(ctx, { tool_name: 'Edit', tool_input: { file_path: list, old_string: '/fake/work', new_string: '' } }, 'guard-config');
    expectRule(ctx, bash(`echo > ${list}`), 'guard-config');
    expectRule(ctx, bash('rm ~/.config/mac-yolo/work-folders'), 'guard-config');
    expectRule(ctx, bash('cp /tmp/x ~/.local/share/mac-yolo-safeguards/mac-yolo-credential-guard.js'), 'guard-config');
    expectRule(ctx, bash(`python3 -c "open('${list}','w').write('')"`), 'guard-config');
    expectAllow(ctx, bash(`cat ${list}`));
    expectAllow(ctx, bash(`cat ${list} 2>/dev/null`));
    expectRule(ctx, bash('cd ~/.config && rm -rf mac-yolo'), 'guard-config');
    expectRule(ctx, bash('cd ~/.config/mac-yolo && rm work-folders'), 'guard-config');
    expectAllow(ctx, bash('ls ~/.config/mac-yolo 2>&1'));
    expectRule(ctx, bash('mac-yolo-credential-guard uninstall --agent all'), 'guard-config');
    expectRule(ctx, bash('node ~/.local/share/mac-yolo-safeguards/mac-yolo-credential-guard.js uninstall'), 'guard-config');
    expectRule(ctx, bash('bin/mac-yolo-credential-guard work-folders add /x'), 'guard-config');
    expectRule(ctx, bash('mac-yolo-credential-guard fix tmp-copy:1234 --yes'), 'guard-config');
    expectAllow(ctx, bash('mac-yolo-credential-guard doctor --json'));

    // Read-only use of the guard and its hook files passes, however the command is written.
    const G_ = 'mac-yolo-credential-guard';
    const hookFiles = ['.claude/settings.json', '.codex/hooks.json', '.cursor/hooks.json'].map((f) => path.join(ctx.home, f));
    for (const c of [
      `node tools/${G_}.js doctor`,
      `node tools/${G_}.js doctor --json`,
      `cd /repo && node tools/${G_}.js doctor 2>&1 | head -20`,
      `bin/${G_} doctor`,
      `bin/${G_} check -- security dump-keychain`,
      `bin/${G_} work-folders list`,
      `bin/${G_} work-folders`,
      `bin/${G_} --help`,
      `node ~/.local/share/mac-yolo-safeguards/${G_}.js doctor`,
      `grep credential-guard ~/.claude/settings.json`,
      `grep -n "credential-guard" ${hookFiles.join(' ')} 2>&1`,
      `cat ~/.cursor/hooks.json`,
      `jq .hooks ~/.claude/settings.json`,
      `jq .hooks.PreToolUse ~/.codex/hooks.json > /tmp/codex-hooks.json`,
      `cat ~/.local/share/mac-yolo-safeguards/${G_}.js | head`,
      `cp ~/.claude/settings.json /tmp/settings-copy.json`,
      `git diff tools/${G_}.js`,
    ]) expectAllow(ctx, { ...bash(c), cwd: '/repo' });
    expectAllow(ctx, { tool_name: 'Read', tool_input: { file_path: hookFiles[0] } });

    // Writes stay blocked: the guard's own write commands, and edits to the hook files.
    for (const c of [
      `bin/${G_} install --agent all`,
      `node tools/${G_}.js install --agent claude`,
      `cd /repo && node tools/${G_}.js uninstall --agent all`,
      `bin/${G_} fix tmp-copy:1234`,
      `yes | bin/${G_} fix auto-approve:abcd`,
      `bin/${G_} work-folders add /x`,
      `bin/${G_} work-folders remove /x`,
      `sed -i '' /credential-guard/d ~/.claude/settings.json`,
      `jq 'del(.hooks)' ~/.claude/settings.json > ~/.claude/settings.json.new && mv ~/.claude/settings.json.new ~/.claude/settings.json`,
      `echo {} > ~/.codex/hooks.json`,
      `cd ~/.cursor && echo {} > hooks.json`,
      `rm ~/.cursor/hooks.json`,
      `cp /tmp/x.json ~/.claude/settings.json`,
      `tee ~/.codex/hooks.json < /tmp/x`,
      `python3 -c "import json; json.dump({}, open('${hookFiles[0]}', 'w'))"`,
    ]) expectRule(ctx, { ...bash(c), cwd: '/repo' }, 'guard-config');

    // Edit and Write tools: other settings may change, the guard's entry may not be removed.
    write(hookFiles[0], JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ hooks: [{ command: `node /x/${G_}.js hook --agent claude` }] }] } }));
    expectAllow(ctx, { tool_name: 'Edit', tool_input: { file_path: hookFiles[0], old_string: '"model": "x"', new_string: '"model": "y"' } });
    expectAllow(ctx, { tool_name: 'Write', tool_input: { file_path: hookFiles[0], content: `{"model":"y","hooks":{"PreToolUse":[{"hooks":[{"command":"node /x/${G_}.js hook"}]}]}}` } });
    expectRule(ctx, { tool_name: 'Write', tool_input: { file_path: hookFiles[0], content: '{"model":"y"}' } }, 'guard-config');
    expectRule(ctx, { tool_name: 'Edit', tool_input: { file_path: hookFiles[0], old_string: `node /x/${G_}.js hook --agent claude`, new_string: 'true' } }, 'guard-config');
    expectRule(ctx, { tool_name: 'MultiEdit', tool_input: { file_path: hookFiles[0], edits: [{ old_string: `${G_}.js`, new_string: 'x.js' }] } }, 'guard-config');
    fs.rmSync(hookFiles[0]);
    // Other tools that share the install folder are not blocked.
    expectAllow(ctx, bash('cp /tmp/x ~/.local/share/mac-yolo-safeguards/mac-yolo-agent-guard.js'));
  });
  req('REQ-10', () => {
    // The blocked-actions summary holds program and flag names, never argument values. Only git, gh, security,
    // launchctl, npm, node and python3 may show a subcommand word.
    const sum = (command) => G.actionSummary({ tool_name: 'Bash', tool_input: { command } }, '/Users/x');
    assert.strictEqual(sum('echo hunter2'), 'echo …');
    assert.strictEqual(sum('cat id_rsa'), 'cat …');
    assert.strictEqual(sum('mysql -phunter2secret'), 'mysql …');
    assert.strictEqual(sum(['curl', '--user', 'admin:pw', 'https://h.example/x'].join(' ')), 'curl --user …');
    assert.strictEqual(sum('git push origin main'), 'git push …');
    assert.strictEqual(sum('launchctl bootout gui/501/com.x'), 'launchctl bootout …');
    assert.strictEqual(sum('rm -rf build'), 'rm -rf …');
    assert.strictEqual(sum('tar -xzf a.tgz'), 'tar -xzf …');
    // Short glued values and script file names are not flag names or subcommands.
    assert.strictEqual(sum('mysql -ppass'), 'mysql …');
    assert.strictEqual(sum('python3 customer-secret-sync.py'), 'python3 …');
    assert.strictEqual(sum('node deploy.js --prod'), 'node --prod …');
    for (const c of ['echo hunter2', 'cat id_rsa', 'mysql -phunter2secret', 'sshpass -p hunter2 ssh h']) {
      assert.doesNotMatch(sum(c), /hunter2|id_rsa/, c);
    }
  });
  req('REQ-11', () => {
    // Install on an empty HOME writes the guard script and no agent config; only existing agents get a hook.
    const { ctx } = makeCtx();
    const res = G.install(ctx, 'all');
    assert.deepStrictEqual(res.changed, []);
    assert.deepStrictEqual(res.skipped, ['claude', 'codex', 'cursor'], 'skipped agents are reported');
    for (const d of ['.claude', '.codex', '.cursor']) assert.ok(!fs.existsSync(path.join(ctx.home, d)), `${d} not created`);
    fs.mkdirSync(path.join(ctx.home, '.codex'), { recursive: true });
    const preGuard = `${JSON.stringify({ hooks: { Stop: [{ command: 'my-stop-hook' }] } })}\n`;
    fs.writeFileSync(path.join(ctx.home, '.codex', 'hooks.json'), preGuard);
    assert.strictEqual(G.install(ctx).changed.length, 1);
    assert.ok(fs.existsSync(path.join(ctx.home, '.codex', 'hooks.json')));
    assert.ok(!fs.existsSync(path.join(ctx.home, '.cursor')) && !fs.existsSync(path.join(ctx.home, '.claude')));
    // Naming an agent still creates its config.
    G.install(ctx, 'cursor');
    assert.ok(fs.existsSync(path.join(ctx.home, '.cursor', 'hooks.json')));

    // Only the newest 5 hooked backups of a file stay; backups without our hook are never pruned.
    const file = path.join(ctx.home, '.codex', 'hooks.json');
    let t = Date.parse('2026-11-20T10:00:00Z');
    ctx.now = () => new Date(t += 1000);
    for (let i = 0; i < 8; i += 1) {
      G.uninstall(ctx, 'codex');
      G.install(ctx, 'codex');
    }
    const all = () => fs.readdirSync(path.dirname(file)).filter((x) => x.startsWith('hooks.json.mac-yolo-backup-')).sort();
    const hooked = () => all().filter((x) => fs.readFileSync(path.join(path.dirname(file), x), 'utf8').includes('mac-yolo-credential-guard'));
    assert.strictEqual(hooked().length, 5);
    const newest = hooked();
    G.uninstall(ctx, 'codex');
    assert.strictEqual(hooked().length, 5);
    assert.ok(hooked().at(-1) > newest.at(-1), 'the newest hooked backup is kept');
    assert.ok(!hooked().includes(newest[0]), 'the oldest hooked backup is dropped');
    assert.strictEqual(fs.readFileSync(`${file}.mac-yolo-original`, 'utf8'), preGuard, 'the first copy is kept for good');
  });

  req('REQ-12', () => {
    // The person's config from before the guard survives any number of hooked backups.
    const { ctx } = makeCtx();
    const dir = path.join(ctx.home, '.claude');
    const file = path.join(dir, 'settings.json');
    fs.mkdirSync(dir, { recursive: true });
    const pre = JSON.stringify({ model: 'mine', hooks: { Stop: [{ hooks: [{ type: 'command', command: 'stop-hook' }] }] } });
    const oldHooked = JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: '"/old/node" "/old/mac-yolo-credential-guard.js" hook --agent claude' }] }] } });
    fs.writeFileSync(`${file}.mac-yolo-backup-2026-01-01T00-00-00-000Z`, pre);
    for (let i = 1; i <= 6; i += 1) fs.writeFileSync(`${file}.mac-yolo-backup-2026-02-0${i}T00-00-00-000Z`, oldHooked);
    fs.writeFileSync(file, oldHooked); // already hooked, but with another path, so install rewrites it
    G.install(ctx, 'claude');
    const names = fs.readdirSync(dir).filter((x) => x.startsWith('settings.json.mac-yolo-backup-'));
    assert.ok(names.includes('settings.json.mac-yolo-backup-2026-01-01T00-00-00-000Z'), 'the pre-guard backup is still there');
    assert.strictEqual(fs.readFileSync(path.join(dir, names[0]), 'utf8'), pre);
    assert.strictEqual(names.length, 6, 'the pre-guard backup plus the newest 5 hooked ones');
    assert.ok(!fs.existsSync(`${file}.mac-yolo-original`), 'the original is never copied from a hooked file');

    // A config without our hook is saved as the original on its first rewrite, and stays.
    const { ctx: c2 } = makeCtx();
    const f2 = path.join(c2.home, '.claude', 'settings.json');
    fs.mkdirSync(path.dirname(f2), { recursive: true });
    fs.writeFileSync(f2, pre);
    G.install(c2, 'claude');
    assert.strictEqual(fs.readFileSync(`${f2}.mac-yolo-original`, 'utf8'), pre);
    for (let i = 0; i < 9; i += 1) { G.uninstall(c2, 'claude'); G.install(c2, 'claude'); }
    assert.strictEqual(fs.readFileSync(`${f2}.mac-yolo-original`, 'utf8'), pre);

    // Many uninstall/install cycles leave a bounded number of backups, and the original stays.
    const { ctx: c3 } = makeCtx();
    const f3 = path.join(c3.home, '.claude', 'settings.json');
    fs.mkdirSync(path.dirname(f3), { recursive: true });
    fs.writeFileSync(f3, pre);
    let t3 = Date.parse('2026-11-20T10:00:00Z');
    c3.now = () => new Date(t3 += 1000);
    G.install(c3, 'claude');
    for (let i = 0; i < 12; i += 1) { G.uninstall(c3, 'claude'); G.install(c3, 'claude'); }
    const files3 = fs.readdirSync(path.dirname(f3)).filter((x) => x.startsWith('settings.json.mac-yolo-backup-'));
    assert.ok(files3.length <= 11, `${files3.length} backups after 12 cycles`);
    assert.strictEqual(fs.readFileSync(`${f3}.mac-yolo-original`, 'utf8'), pre);
    assert.ok(files3.some((x) => fs.readFileSync(path.join(path.dirname(f3), x), 'utf8') === pre), 'the oldest pre-guard backup is still there');

    // A pre-guard config that only mentions the guard's name is still a pre-guard config.
    const { ctx: c4 } = makeCtx();
    const f4 = path.join(c4.home, '.claude', 'settings.json');
    fs.mkdirSync(path.dirname(f4), { recursive: true });
    const noted = JSON.stringify({ model: 'mine', note: 'remove mac-yolo-credential-guard later', hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo mac-yolo-credential-guard is not installed' }] }] } });
    fs.writeFileSync(f4, noted);
    let t4 = Date.parse('2026-11-20T11:00:00Z');
    c4.now = () => new Date(t4 += 1000);
    G.install(c4, 'claude');
    assert.strictEqual(fs.readFileSync(`${f4}.mac-yolo-original`, 'utf8'), noted, 'saved as the original');
    for (let i = 0; i < 9; i += 1) { G.uninstall(c4, 'claude'); G.install(c4, 'claude'); }
    assert.strictEqual(fs.readFileSync(`${f4}.mac-yolo-original`, 'utf8'), noted);
    assert.ok(fs.readdirSync(path.dirname(f4)).some((x) => x.startsWith('settings.json.mac-yolo-backup-') && fs.readFileSync(path.join(path.dirname(f4), x), 'utf8') === noted), 'a backup of it remains');
  });

  req('REQ-13', () => {
    // A guard that differs from the app's copy is saved before it is replaced; the newest 3 saves are kept.
    const { ctx } = makeCtx();
    const dest = path.join(ctx.home, '.local', 'share', 'mac-yolo-safeguards', 'mac-yolo-credential-guard.js');
    G.install(ctx, 'all');
    assert.deepStrictEqual(fs.readdirSync(path.dirname(dest)).filter((x) => x.includes('.replaced-')), [], 'nothing replaced on a first install');
    let t = Date.parse('2026-11-20T10:00:00Z');
    ctx.now = () => new Date(t += 1000);
    for (let i = 1; i <= 5; i += 1) {
      fs.writeFileSync(dest, `// newer guard ${i}\n`);
      G.install(ctx, 'all');
      assert.strictEqual(fs.readFileSync(dest, 'utf8'), fs.readFileSync(TOOL, 'utf8'));
    }
    const saved = fs.readdirSync(path.dirname(dest)).filter((x) => x.includes('.replaced-')).sort();
    assert.strictEqual(saved.length, 3);
    assert.strictEqual(fs.readFileSync(path.join(path.dirname(dest), saved.at(-1)), 'utf8'), '// newer guard 5\n');
    assert.strictEqual(fs.readFileSync(path.join(path.dirname(dest), saved[0]), 'utf8'), '// newer guard 3\n');

    // Two saves in the same millisecond both exist.
    const { ctx: c2 } = makeCtx();
    const dest2 = path.join(c2.home, '.local', 'share', 'mac-yolo-safeguards', 'mac-yolo-credential-guard.js');
    G.install(c2, 'all');
    const frozen = new Date('2026-11-20T10:00:00.000Z');
    c2.now = () => frozen;
    fs.writeFileSync(dest2, '// one\n'); G.install(c2, 'all');
    fs.writeFileSync(dest2, '// two\n'); G.install(c2, 'all');
    const same = fs.readdirSync(path.dirname(dest2)).filter((x) => x.includes('.replaced-')).sort();
    assert.strictEqual(same.length, 2, 'both saves exist');
    assert.deepStrictEqual(same.map((x) => fs.readFileSync(path.join(path.dirname(dest2), x), 'utf8')), ['// one\n', '// two\n']);

    // A save that fails leaves the live guard alone and reports it.
    const { ctx: c3 } = makeCtx();
    const dir3 = path.join(c3.home, '.local', 'share', 'mac-yolo-safeguards');
    const dest3 = path.join(dir3, 'mac-yolo-credential-guard.js');
    G.install(c3, 'all');
    fs.writeFileSync(dest3, '// live guard\n');
    fs.chmodSync(dir3, 0o555);
    try {
      const r = G.install(c3, 'all');
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /left in place/);
      assert.strictEqual(fs.readFileSync(dest3, 'utf8'), '// live guard\n', 'the live guard stays');
      const cli = require('child_process').spawnSync(process.execPath, [TOOL, 'install'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', HOME: c3.home } });
      assert.notStrictEqual(cli.status, 0, 'the command exits non-zero');
      assert.match(cli.stderr, /left in place/);
      assert.strictEqual(fs.readFileSync(dest3, 'utf8'), '// live guard\n');
    } finally { fs.chmodSync(dir3, 0o755); }
  });
} finally {
  fs.rmSync(BASE, { recursive: true, force: true });
}

assert.deepStrictEqual(passed, ['REQ-01', 'REQ-02', 'REQ-03', 'REQ-04', 'REQ-05', 'REQ-06', 'REQ-07', 'REQ-08', 'REQ-09', 'REQ-10', 'REQ-11', 'REQ-12', 'REQ-13']);
console.log(`ok - ${passed.length} requirement groups passed`);
