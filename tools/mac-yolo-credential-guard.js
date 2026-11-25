#!/usr/bin/env node
'use strict';

/**
 * tools/mac-yolo-credential-guard.js: keeps AI coding agents away from the Mac's credentials.
 *
 * An endpoint security tool on one Mac running unattended agents raised 2,256 alerts in two months, all from
 * the agents: keychain reads for "Chrome Safe Storage", copies of Chrome's Cookies and Login Data into /tmp,
 * API keys set machine-wide with `launchctl setenv`, a recorder reinstalled with its quarantine flag stripped,
 * agents in auto-approve modes, and a hook that ran an inline socket script on every event.
 *
 *   hook [--agent claude|codex|cursor]   PreToolUse hook: deny before the call runs (exit 2)
 *   check -- <command>                   evaluate one shell command (exit 3 on deny)
 *   doctor [--json]                      read-only audit of what is already on this Mac (exit 1 on findings)
 *   fix <id> [--yes]                     fix one doctor finding after a y answer; moves files to Trash
 *   install [--agent claude|codex|cursor|all]    register the hook (keeps existing hooks, backs up configs)
 *   uninstall [--agent ...]              remove only this guard's hook entries
 *   work-folders [list|add <path>]       opt-in folders that agents without MAC_YOLO_WORK_AGENT=1 are refused in
 *
 * Design: docs/designs/2026-11-19-agent-credential-guards.md. Every function takes a ctx (home, env, temp
 * roots, PATH dirs, log dir, process runner), built at call time, so tests never touch the real Mac.
 * Not covered: a program the agent runs (a test suite, a script file) that calls the keychain itself. The
 * hook sees the agent's command line, not what that program does after it starts.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const MARKER = 'mac-yolo-credential-guard';
const AGENTS = ['claude', 'codex', 'cursor'];

function defaultCtx() {
  const home = process.env.HOME || os.homedir();
  return {
    home,
    env: process.env,
    tmpRoots: [...new Set(['/private/tmp', fs.realpathSync(os.tmpdir())])],
    pathDirs: (process.env.PATH || '').split(':').filter(Boolean),
    appDirs: ['/Applications', path.join(home, 'Applications')],
    logDir: path.join(home, 'Library', 'Logs', 'mac-yolo'),
    nodePath: process.execPath,
    ppid: process.ppid,
    run: (cmd, args, opts = {}) => {
      const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout || 5000 });
      return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
    },
    now: () => new Date(),
  };
}

const configDir = (ctx) => path.join(ctx.home, '.config', 'mac-yolo');
const installDir = (ctx) => path.join(ctx.home, '.local', 'share', 'mac-yolo-safeguards');

// ---------------------------------------------------------------- matching

function normalize(text, home) {
  let s = String(text || '');
  s = s.replace(/\\(.)/g, '$1'); // Login\ Data -> Login Data
  s = s.replace(/``|\$\(\)/g, ''); // an empty substitution joins words: sec``urity runs security
  s = s.replace(/`/g, ' ; '); // `cmd` is a command of its own, not text of the one around it
  s = s.replace(/["']/g, ''); // sec""urity runs security in a shell, so quotes are removed, not spaced
  s = s.replace(/\$\{HOME\}|\$HOME\b/g, home).replace(/(^|[\s=:(,[])~(?=\/|\s|$)/g, `$1${home}`);
  return s;
}

const SECURITY_WORD = '(?:^|[\\s;&|(,\\[/=])security[\\s,\\]]+(?:-\\S+[\\s,]+)*';
const KEYCHAIN_READ_RE = new RegExp(
  `${SECURITY_WORD}(find-generic-password|find-internet-password|dump-keychain|export|find-key)\\b`,
);
const KEYCHAIN_PATH_RE = /\/Library\/Keychains\/|\.keychain(-db)?$/;
// Browser data folders named without the full path: `cd ~/Library/Application Support/Google && cp Chrome/...`, globs.
const BROWSER_VENDOR_RE = /Library\/Application[^/]{0,12}\/(?:Google|BraveSoftware|Microsoft Edge|Arc|Chromium|Vivaldi|Firefox)(?=[/\s;&|)]|$)/;

const BROWSER_ROOTS = [
  'Library/Application Support/Google/Chrome',
  'Library/Application Support/Google/Chrome Beta',
  'Library/Application Support/Google/Chrome Canary',
  'Library/Application Support/BraveSoftware/Brave-Browser',
  'Library/Application Support/Microsoft Edge',
  'Library/Application Support/Arc/User Data',
  'Library/Application Support/Chromium',
  'Library/Application Support/Vivaldi',
];
const CHROMIUM_STORE_RE = /(?:^|\/|\s)(Cookies|Login Data(?: For Account)?|Local State|Web Data)(?:-journal)?(?=$|[\s/;&|),\]}])/;
const SAFARI_COOKIES_RE = /\/Library\/Containers\/com\.apple\.Safari\/Data\/Library\/Cookies\//;
const safariCookies = (s, home) => SAFARI_COOKIES_RE.test(s) || s.includes(`${home}/Library/Cookies/`);
const FIREFOX_RE = /Firefox\/Profiles\/[^\s]*(cookies\.sqlite|logins\.json|key4\.db)/;
const COPY_TOOL_RE = /(?:^|[\s;&|(/])(cp|mv|ln|ditto|rsync|tar|zip|scp|sqlite3|cat|strings|xxd|base64|dd|python[0-9.]*|node|perl|ruby)(?=\s)/;
const COOKIE_LIB_RE = /\b(browser_cookie3|pycookiecheat|rookiepy|chrome-cookies-secure|chrome_cookies)\b/;
const XATTR_RE = /(?:^|[\s;&|(/])xattr\s+([^;&|\n]*)/g;
const LAUNCHCTL_SETENV_RE = /(?:^|[\s;&|(/])launchctl\s+(?:config\s+user\s+)?setenv\s+([^;&|\n]*)/g;
const SECRET_WORD_RE = /KEY|TOKEN|SECRET|PASS|CRED|AUTH|PRIVATE|SESSION|COOKIE|(?:^|_)PAT(?:_|$)/i;
// Names that match a secret word but hold a socket path or a setting, never a secret.
const NOT_SECRET = new Set(['SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'KEYTIMEOUT', 'XPC_SERVICE_NAME', 'PASSWORD_STORE_DIR']);
const SECRET_NAME_RE = { test: (n) => SECRET_WORD_RE.test(n) && !NOT_SECRET.has(String(n).toUpperCase()) };
const INTERPRETER_RE = /(?:^|[\s;&|(/])(python[0-9.]*|node|perl|ruby|osascript|swift)(?=\s)/;
const WRITE_OP_RE = /(?:>|(?:^|[\s;&|(/])(rm|mv|cp|tee|ln|chmod|chflags|truncate|ditto|rsync)\s|sed\s+-i)/;

function referencesBrowserRoot(s) {
  return BROWSER_ROOTS.some((root) => s.includes(root)) || s.includes('Library/Application Support/Firefox');
}

function inside(p, dir) {
  const a = path.resolve(p);
  const b = path.resolve(dir);
  return a === b || a.startsWith(b.endsWith('/') ? b : `${b}/`);
}

function readWorkFolders(ctx) {
  try {
    return fs.readFileSync(path.join(configDir(ctx), 'work-folders'), 'utf8')
      .split('\n').map((l) => l.replace(/#.*/, '').trim()).filter((l) => l.startsWith('/'));
  } catch {
    return [];
  }
}

// Every rule has an ID (the key), a MITRE ATT&CK technique and a default mode. Modes: block denies the call, ask
// denies it until a person approves that exact call in the menu bar (once, within 10 minutes), warn allows it with
// a message, log allows it silently. Warn and log write a log line; so does every other mode. The person sets modes in
// ~/.config/mac-yolo/credential-guard.json. Techniques were checked on attack.mitre.org on 2026-11-19; the
// reasons for the approximate ones are in docs/designs/2026-11-19-falcon-style-rules.md.
const RULES = Object.fromEntries(Object.entries({
  keychain: {
    technique: 'T1555.001', defaultMode: 'block',
    reason: 'reads the macOS keychain',
    alternative: 'pass the one secret this task needs into the agent\'s environment from your own terminal or secret manager',
  },
  'keychain-file': {
    technique: 'T1555.001', defaultMode: 'block',
    reason: 'opens a keychain database file',
    alternative: 'pass the one secret this task needs into the agent\'s environment from your own terminal or secret manager',
  },
  'browser-store': {
    technique: 'T1555.003', defaultMode: 'block',
    reason: 'reads or copies a browser cookie or password store',
    alternative: 'use a separate browser profile made for the agent (for example a headless Playwright profile), never your own',
  },
  'cookie-library': {
    technique: 'T1539', defaultMode: 'block',
    reason: 'loads a library that decrypts browser cookies',
    alternative: 'use a separate browser profile made for the agent, or the site\'s API with a token you issue for it',
  },
  quarantine: {
    technique: 'T1553.001', defaultMode: 'block',
    reason: 'strips the macOS quarantine flag, which turns off the Gatekeeper check',
    alternative: 'install the app from its signed release, or open it once from Finder so macOS checks it',
  },
  'launchctl-secret': {
    technique: 'T1552', defaultMode: 'block',
    reason: 'sets a secret in the launchd environment, where every process on the Mac can read it',
    alternative: 'export it only in the shell or wrapper of the one program that needs it',
  },
  'guard-config': {
    technique: 'T1685', defaultMode: 'block',
    reason: 'changes the credential guard\'s own settings',
    alternative: 'edit the guard settings yourself in a terminal',
  },
  'work-folder': {
    technique: 'T1213', defaultMode: 'block',
    reason: 'works inside a folder listed as work-only, from an agent not marked as a work agent',
    alternative: 'use an agent started with MAC_YOLO_WORK_AGENT=1 under your work account for this folder',
  },
  'net-oneliner': {
    technique: 'T1059', defaultMode: 'block',
    reason: 'runs inline interpreter code that opens a network connection, which endpoint security tools treat as an attack',
    alternative: 'use curl for a plain download, or put the code in a script file in the repo where a person can read it',
  },
  'curl-upload': {
    technique: 'T1048', defaultMode: 'log',
    reason: 'uploads a file to a host that is not on the upload allowlist',
    alternative: 'if this upload is expected, a person adds the host to uploadAllowlist in ~/.config/mac-yolo/credential-guard.json',
  },
  recorder: {
    technique: 'T1113', defaultMode: 'block',
    reason: 'installs or starts a screen or audio recorder',
    alternative: 'a person installs and starts recorders by hand, outside agent sessions',
  },
  'banned-agent': {
    technique: 'T1567', defaultMode: 'block',
    reason: 'runs an agent program that the owner of this Mac has banned',
    alternative: 'use an agent the owner allows on this Mac; the ban list is bannedAgents in ~/.config/mac-yolo/credential-guard.json',
  },
  // The rules below follow CrowdStrike's public macOS write-ups (SHAMOS, ClickFix) and MITRE ATT&CK; see
  // docs/endpoint-security-alignment.md. They apply to every agent the hook runs for, not only Claude Code.
  'pipe-to-shell': {
    technique: 'T1059.004', defaultMode: 'block',
    reason: 'pipes a download (or decoded text) straight into a shell or osascript, the delivery pattern of macOS stealers',
    alternative: 'download the script to a file in the repo, read it, then run that file',
  },
  'tmp-exec': {
    technique: 'T1204.002', defaultMode: 'block',
    reason: 'runs a program from /tmp, where endpoint security expects dropped malware',
    alternative: 'build or install the program inside the project folder and run it from there',
  },
  tcc: {
    technique: 'T1548.006', defaultMode: 'block',
    reason: 'resets or reads macOS privacy permissions (tccutil or the TCC database)',
    alternative: 'a person changes privacy permissions in System Settings > Privacy & Security',
  },
  'launch-agent': {
    technique: 'T1543.001', defaultMode: 'ask',
    reason: 'installs, loads or disables a LaunchAgent or LaunchDaemon, which keeps a program running at every login',
    alternative: 'ask the person to approve this one call in the Mac YOLO menu bar, or to install the LaunchAgent themselves',
  },
  falcon: {
    technique: 'T1562.001', defaultMode: 'block',
    reason: 'touches the CrowdStrike Falcon sensor, its files or its settings',
    alternative: 'leave the security agent alone; questions about it go to the Mac\'s IT or security team',
  },
}).map(([id, r]) => [id, { id, ...r }]));

const MODES = ['log', 'warn', 'ask', 'block'];
// The rules that guard credentials. A mode below block on one of these is a high doctor finding.
const CREDENTIAL_RULES = ['keychain', 'keychain-file', 'browser-store', 'cookie-library', 'quarantine', 'launchctl-secret', 'guard-config', 'work-folder', 'pipe-to-shell', 'tmp-exec', 'tcc', 'falcon'];
const SETTINGS_FILE = 'credential-guard.json';
const DEFAULT_UPLOAD_ALLOW = ['localhost', '127.0.0.1', '::1'];
// screenpi.pe is screenpipe's installer domain.
const DEFAULT_RECORDERS = ['screenpipe', 'screenpi.pe'];

const isHostEntry = (h) => h === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')
  || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(h);

const NAME_RE = /^[a-z0-9][a-z0-9._-]{2,}$/i;
const STRICTNESS = { log: 0, warn: 1, ask: 2, block: 3 };

/**
 * Reads ~/.config/mac-yolo/credential-guard.json. An invalid file can only make the guard stricter: each rule keeps
 * the stricter of its default and a valid value from the file, the name lists keep their valid names, and the
 * upload allowlist falls back to the default. guard-config stays block whatever the file says.
 */
function loadSettings(ctx) {
  const modes = Object.fromEntries(Object.values(RULES).map((r) => [r.id, r.defaultMode]));
  const out = {
    modes, allowlist: DEFAULT_UPLOAD_ALLOW, recorders: DEFAULT_RECORDERS, bannedAgents: [], problems: [], pinned: false, downgraded: [], agentModes: {},
  };
  let raw;
  try { raw = fs.readFileSync(path.join(configDir(ctx), SETTINGS_FILE), 'utf8'); } catch { return out; }
  let cfg;
  try { cfg = JSON.parse(raw); } catch { out.problems.push('it is not valid JSON'); return out; }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) { out.problems.push('it is not a JSON object'); return out; }
  const problems = out.problems;
  const fileModes = {};
  const rules = cfg.rules === undefined ? {} : cfg.rules;
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) problems.push('"rules" is not an object');
  else {
    for (const [id, m] of Object.entries(rules)) {
      if (!RULES[id]) problems.push(`unknown rule "${id}"`);
      else if (!MODES.includes(m)) problems.push(`rule "${id}" has mode ${JSON.stringify(m)}, not log, warn, ask or block`);
      else fileModes[id] = m;
    }
  }
  const lists = {};
  for (const key of ['uploadAllowlist', 'recorders', 'bannedAgents']) {
    const v = cfg[key];
    if (v === undefined) { lists[key] = []; continue; }
    if (!Array.isArray(v)) { problems.push(`"${key}" is not a list`); lists[key] = []; continue; }
    const ok = key === 'uploadAllowlist' ? (x) => isHostEntry(x) : (x) => NAME_RE.test(x);
    const clean = v.filter((x) => typeof x === 'string').map((x) => x.trim().toLowerCase());
    if (clean.length !== v.length || clean.some((x) => !ok(x))) problems.push(`"${key}" has an entry that is not ${key === 'uploadAllowlist' ? 'a full host name' : 'a program name'}`);
    lists[key] = clean.filter(ok);
  }
  const invalid = problems.length > 0;
  for (const [id, m] of Object.entries(fileModes)) {
    if (!invalid || STRICTNESS[m] > STRICTNESS[modes[id]]) modes[id] = m;
  }
  if (modes['guard-config'] !== 'block') { out.pinned = true; modes['guard-config'] = 'block'; }
  out.agentModes = agentOverrides(cfg.agents, modes, problems);
  // ask is not a downgrade: the call still needs a person's approval each time.
  out.downgraded = CREDENTIAL_RULES.filter((id) => modes[id] !== 'block' && modes[id] !== 'ask');
  if (!invalid) out.allowlist = [...new Set([...DEFAULT_UPLOAD_ALLOW, ...lists.uploadAllowlist])];
  out.recorders = [...new Set([...DEFAULT_RECORDERS, ...lists.recorders])];
  out.bannedAgents = [...new Set(lists.bannedAgents)];
  return out;
}

/**
 * Per-agent overrides: { "agents": { "codex": { "rules": { "launch-agent": "block" } } } }. An override can only make
 * a rule stricter for that agent; a looser one is ignored and reported, so no agent can be given a weaker guard.
 * Problems found here are reported but don't touch the shared settings above.
 */
function agentOverrides(agents, modes, problems) {
  const out = {};
  if (agents === undefined) return out;
  if (!agents || typeof agents !== 'object' || Array.isArray(agents)) { problems.push('"agents" is not an object'); return out; }
  for (const [agent, v] of Object.entries(agents)) {
    if (!AGENTS.includes(agent)) { problems.push(`unknown agent "${agent}" in "agents" (use ${AGENTS.join(', ')})`); continue; }
    const rules = v && typeof v === 'object' && !Array.isArray(v) ? v.rules : undefined;
    if (!rules || typeof rules !== 'object' || Array.isArray(rules)) { problems.push(`"agents.${agent}.rules" is not an object`); continue; }
    for (const [id, m] of Object.entries(rules)) {
      if (!RULES[id]) problems.push(`unknown rule "${id}" in "agents.${agent}"`);
      else if (!MODES.includes(m)) problems.push(`rule "${id}" in "agents.${agent}" has mode ${JSON.stringify(m)}, not log, warn, ask or block`);
      else if (STRICTNESS[m] < STRICTNESS[modes[id]]) problems.push(`"agents.${agent}" sets "${id}" to ${m}, looser than ${modes[id]}; an agent override can only be stricter, so it is ignored`);
      else if (STRICTNESS[m] > STRICTNESS[modes[id]]) (out[agent] = out[agent] || {})[id] = m;
    }
  }
  return out;
}

/** The settings one agent runs under: the shared modes with that agent's stricter overrides applied. */
function settingsFor(settings, agent) {
  const extra = settings && settings.agentModes && settings.agentModes[agent];
  if (!extra) return settings;
  const modes = { ...settings.modes, ...extra };
  return { ...settings, modes, downgraded: CREDENTIAL_RULES.filter((id) => modes[id] !== 'block' && modes[id] !== 'ask') };
}

const PATH_KEY_RE = /path|file|dir|target|source|dest|src|cwd|uri|url/i;
const SKIP_KEY_RE = /^(content|new_string|old_string|edits|contents|text|description|prompt)$/i;

function pathFields(value, key = '', out = []) {
  if (typeof value === 'string') {
    if (PATH_KEY_RE.test(key)) out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) pathFields(v, key, out);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (!SKIP_KEY_RE.test(k)) pathFields(v, k, out);
    }
  }
  return out;
}

function commandOf(payload) {
  const input = payload.tool_input || payload.toolInput || {};
  let c = input.command ?? input.cmd ?? input.CommandLine;
  if (c === undefined && typeof payload.command === 'string') c = payload.command;
  if (Array.isArray(c)) c = c.join(' ');
  return typeof c === 'string' ? c : '';
}

function isWriteTool(name) {
  return /^(Write|Edit|MultiEdit|NotebookEdit|write_file|edit_file|replace|apply_patch|write_to_file|replace_file_content)$/i.test(name || '');
}

// A command is split into parts at ; & | newlines, backticks, $( ( ) { }. The keychain, quarantine and launchctl
// rules then fail closed: the word pair (`security dump-keychain`, `xattr -c`, `launchctl setenv TOKEN`) anywhere in
// a part is denied, unless that part runs a text-only command (a commit message, an echo, a search). Shell keywords
// and launchers in front (`then`, `sudo -u x`, `timeout 5`) don't matter, because the pair is found anywhere.
// Bare `security` / `security -i` (commands read from stdin) is checked by program name, so `ls src/security`
// and `npm run security` stay allowed.
const LAUNCHERS = new Set(['sudo', 'env', 'exec', 'command', 'builtin', 'nohup', 'time', 'timeout', 'gtimeout', 'xargs',
  'nice', 'caffeinate', 'arch', 'doas', 'then', 'do', 'else', 'if', 'while', 'until', '!']);
const INTERPRETER_HEAD_RE = /^(python[0-9.]*|node|ruby|perl|osascript|sh|bash|zsh|fish|swift|deno|bun|eval|source|\.)$/;
const TEXT_ONLY = (seg) => /^(echo|printf|grep|egrep|rg|ag|ack)$/.test(seg.head)
  || (seg.head === 'git' && /^(commit|log|tag|show|grep)$/.test(seg.args.find((a) => !a.startsWith('-')) || ''))
  || (seg.head === 'gh' && /^(pr|issue|release)$/.test(seg.args[0] || '') && /^(create|comment|edit|view|list)$/.test(seg.args[1] || ''));

function segments(cmd) {
  return cmd.split(/[;&|\n`(){}]+|\$\(/).map((text) => {
    const words = text.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < words.length) {
      const w = words[i];
      if (LAUNCHERS.has(path.basename(w)) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i += 1; continue; }
      const prev = i > 0 ? path.basename(words[i - 1]) : '';
      if (i > 0 && LAUNCHERS.has(prev) && /^-/.test(w)) {
        // Options that take a value: sudo -u user, nice -n 10, env -u NAME.
        i += /^-[ugnCDhpTU]$/.test(w) ? 2 : 1;
        continue;
      }
      if (/^(timeout|gtimeout)$/.test(prev) && /^\d/.test(w)) { i += 1; continue; }
      break;
    }
    return { text: text.trim(), head: words[i] ? path.basename(words[i]) : '', exe: words[i] || '', args: words.slice(i + 1) };
  }).filter((s) => s.head);
}

const KEYRING_RE = /\bimport\s+keyring\b|\bkeyring\.get_password\b|(?:^|\s)keyring\s+get\b/;

/** `security` alone or with -i: it reads its commands from stdin, so there is no subcommand word to match. */
function bareSecurity(seg) {
  if (seg.head !== 'security') return false;
  const flags = seg.args.filter((a) => /^-[a-zA-Z]+$/.test(a)).join('');
  return !seg.args.find((a) => !a.startsWith('-')) || /i/.test(flags);
}

function keychainRead(seg, bareCounts = true) {
  if (bareCounts && bareSecurity(seg)) return true;
  if (TEXT_ONLY(seg)) return false;
  return KEYCHAIN_READ_RE.test(seg.text) || KEYRING_RE.test(seg.text);
}

// ---------------------------------------------------------------- command scanner
//
// One pass over the command text, linear in its length. It splits the text into pipelines of stages and keeps command
// substitutions (`$( )`, backticks, `<( )`, `>( )`) as nested pieces of the stage that holds them. Quotes group words
// (a quoted word is one word, so `echo "run bash later"` has no `bash` word); `$( )` inside double quotes still runs.
// `( )` and `{ }` groups stay inside their stage, so `curl ... | { sh; }` has `sh` in the stage after the pipe.
// Nesting deeper than SCAN_MAX_DEPTH is read as plain text, so a hostile command cannot make the scan recurse.
const SCAN_MAX_DEPTH = 48;
const SP = ''; // a space that sits inside a quoted word
const SUBST = ''; // stands for one substitution inside a stage's text

function scanCommand(raw) {
  const text = String(raw || '');
  const frame = (kind) => ({ kind, pipes: [], stage: { buf: '', subs: [] }, stages: [], group: 0, param: 0, q: '' });
  const stack = [frame('root')];
  const endStage = (f) => { if (f.stage.buf.trim() || f.stage.subs.length) f.stages.push(f.stage); f.stage = { buf: '', subs: [] }; };
  const endPipe = (f) => { endStage(f); if (f.stages.length) f.pipes.push(f.stages); f.stages = []; };
  const close = () => {
    const f = stack.pop();
    endPipe(f);
    const parent = stack[stack.length - 1];
    parent.stage.subs.push({ kind: f.kind, pipes: f.pipes });
    parent.stage.buf += SUBST;
  };
  const open = (kind) => { stack.push(frame(kind)); };
  const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  for (let i = 0; i < text.length; i += 1) {
    const f = stack[stack.length - 1];
    const c = text[i];
    const n = text[i + 1];
    if (f.q === "'") { if (c === "'") f.q = ''; else f.stage.buf += isSpace(c) ? SP : c; continue; }
    if (c === '\\' && n !== undefined) { f.stage.buf += isSpace(n) ? SP : n; i += 1; continue; }
    if (f.q === '"') {
      if (c === '"') f.q = '';
      else if (c === '$' && n === '(' && stack.length < SCAN_MAX_DEPTH) { open('sub'); i += 1; }
      else if (c === '`' && stack.length < SCAN_MAX_DEPTH) { if (f.kind === 'tick') close(); else open('tick'); }
      else f.stage.buf += isSpace(c) ? SP : c;
      continue;
    }
    if (c === "'") { f.q = "'"; continue; }
    if (c === '"') { f.q = '"'; continue; }
    if (c === '`') {
      if (f.kind === 'tick') close();
      else if (stack.length < SCAN_MAX_DEPTH) open('tick');
      continue;
    }
    if (n === '(' && (c === '$' || c === '<' || c === '>') && stack.length < SCAN_MAX_DEPTH) { open(c === '$' ? 'sub' : 'proc'); i += 1; continue; }
    if (c === '$' && n === '{') { f.param += 1; f.stage.buf += '${'; i += 1; continue; }
    if (f.param > 0) { if (c === '}') f.param -= 1; f.stage.buf += isSpace(c) ? ' ' : c; continue; }
    if (c === '(') { f.group += 1; f.stage.buf += ' '; continue; }
    if (c === ')') {
      if (f.group > 0) { f.group -= 1; f.stage.buf += ' '; } else if ((f.kind === 'sub' || f.kind === 'proc') && stack.length > 1) close(); else f.stage.buf += ' ';
      continue;
    }
    if (c === '{' && (n === undefined || isSpace(n))) { f.group += 1; f.stage.buf += ' '; continue; }
    if (c === '}' && f.group > 0) { f.group -= 1; f.stage.buf += ' '; continue; }
    if (c === '|') {
      if (n === '|') { endPipe(f); i += 1; } else { endStage(f); if (n === '&') i += 1; }
      continue;
    }
    if (c === ';' || c === '\n' || c === '&') {
      const redirect = c === '&' && (text[i - 1] === '>' || text[i - 1] === '<' || n === '>');
      if (redirect) { f.stage.buf += c; continue; }
      if (f.group > 0) { f.stage.buf += ' '; continue; }
      if (c === '&' && n === '&') i += 1;
      endPipe(f);
      continue;
    }
    f.stage.buf += isSpace(c) ? ' ' : c;
  }
  while (stack.length > 1) close();
  const root = stack[0];
  endPipe(root);
  return { kind: 'root', pipes: root.pipes };
}

const stageWords = (stage) => stage.buf.split(/\s+/).filter(Boolean).map((w) => w.split(SP).join(' '));
const baseName = (w) => path.basename(w.replace(new RegExp(SUBST, 'g'), ''));
const ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** The stages of a substitution tree, one level (each stage reaches its own substitutions itself). */
const subStages = (sub) => sub.pipes.flat();

/** The text of a stage and everything substituted into it, computed once per stage so deep nesting stays linear. */
function fullText(stage) {
  if (stage.text === undefined) {
    let out = stageWords(stage).join(' ');
    for (const sub of stage.subs) for (const st of subStages(sub)) out += ` ${fullText(st)}`;
    stage.text = out;
  }
  return stage.text;
}

// pipe-to-shell: fetched or decoded text reaches a shell or interpreter. Instead of listing the ways a shell can be
// wrapped (sudo, env, timeout, xargs, su -c, script ...), any shell or interpreter word in a stage after a fetch stage
// is a sink, unless the stage's own command is a plain text tool or the interpreter is given literal code or a script file.
const FETCH_WORDS = new Set(['curl', 'wget', 'fetch', 'aria2c', 'nc', 'ncat', 'netcat', 'socat', 'ssh']);
const SINK_WORD_RE = /^(?:(?:ba|z|da|k|fi|c|tc|a)?sh|osascript|pwsh|powershell|python[0-9.]*|node(?:js)?|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|deno|bun)$/;
const SHELL_WORD_RE = /^(?:(?:ba|z|da|k|fi|c|tc|a)?sh|osascript|pwsh|powershell)$/;
const HARMLESS_HEADS = new Set(['jq', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'head', 'tail', 'tee', 'wc', 'sort', 'uniq', 'cut', 'tr', 'cat',
  'less', 'more', 'awk', 'gawk', 'sed', 'xxd', 'hexdump', 'od', 'echo', 'printf', 'pbcopy', 'shasum', 'sha256sum', 'md5', 'md5sum', 'tar',
  'gzip', 'gunzip', 'zcat', 'bzip2', 'xz', 'diff', 'cmp', 'column', 'fold', 'nl', 'rev', 'yq', 'tac']);
const CODE_DANGER_RE = /\b(?:exec|eval|execfile|system|popen|subprocess|spawn|fork|compile|__import__|child_process|Function|require)\b|/;

const COMPOUND_OPEN = new Set(['if', 'while', 'until', 'for', 'case', 'select']);
const COMPOUND_CLOSE = new Set(['fi', 'done', 'esac']);
const COMPOUND_CONT = new Set(['do', 'then', 'else', 'elif', '!']);
const COMPOUND_WORDS = new Set([...COMPOUND_OPEN, ...COMPOUND_CLOSE, ...COMPOUND_CONT]);
const LAUNCH_SKIP = new Set(['sudo', 'env', 'nice', 'nohup', 'time', 'command', 'exec', 'timeout', 'gtimeout', 'xargs', 'caffeinate', 'doas', 'stdbuf', 'arch', 'setsid']);

function headOf(words) {
  let i = 0;
  while (i < words.length && (ASSIGN_RE.test(words[i]) || COMPOUND_CONT.has(words[i]))) i += 1;
  return i;
}

/** The word that names the program: after assignments, keywords, launchers and their options. */
function commandWord(words) {
  let i = headOf(words);
  while (i < words.length) {
    const w = words[i];
    if (/^-[ugnCDhpTUaIPsStlLE]$/.test(w) && i > headOf(words)) { i += 2; continue; } // sudo -u user, env -u NAME, xargs -I {}
    if (LAUNCH_SKIP.has(baseName(w)) || /^-/.test(w) || /^\d+$/.test(w) || ASSIGN_RE.test(w)) { i += 1; continue; }
    break;
  }
  return i;
}

// A listing pipeline: programs that only read and print. With short options only, none of them runs a program named
// in its input or arguments or writes a file. Every option of theirs that does is a long one (`rg --pre`,
// `rg --hostname-bin`, and where grep and cat are set up as ugrep and bat, `--filter`, `--pager`, `--view`,
// `--save-config`), so a stage with any long option is not a listing stage. sort and uniq are left out because short
// forms do it too (`sort -o`, `uniq in out`), and so are awk, sed, xargs, find, less, tee, echo and every shell.
const LISTING_HEADS = new Set(['ps', 'pgrep', 'grep', 'egrep', 'fgrep', 'rg', 'head', 'tail', 'wc', 'cut', 'tr', 'column', 'cat', 'ls', 'cd']);
const isLongOption = (w) => w.startsWith('--');

/**
 * Is the word `security` in this command only a search pattern in a listing pipeline? The split in `segments` drops
 * quotes, so `ps aux | grep -E "falcon|security"` leaves a part that is only the word, and that part reads like
 * `security` run with no subcommand. The exemption is kept as narrow as the case it is for. All of these must hold:
 * - every stage of the whole command starts with a program in LISTING_HEADS, by bare name: no path (`./grep`), no
 *   assignment or launcher in front (`PATH=. grep`, `sudo grep`), no shell keyword, function or alias definition;
 * - outside quotes the text holds only names, options, paths and `|`, `&`, `;`: no `$`, backtick, bracket, brace,
 *   glob, backslash or redirect (apart from `2>&1` and `>/dev/null`), and no `$` or backtick inside double quotes.
 *   That rules out substitutions, function definitions (`grep() { ...; }`), groups and here-strings;
 * - no long option on any stage.
 * Text can then only be printed: `grep -o` may print the word, but no stage after it can run it.
 */
const HARMLESS_REDIRECT_RE = /\s(?:2>&1|[12]?>\/dev\/null)(?=[\s|;&]|$)/g;
const PLAIN_UNQUOTED_RE = /[A-Za-z0-9_.,/:=+@%~\s|&;-]/;

/** Quote-aware: is every character outside quotes plain, and is nothing expanded inside double quotes? */
function plainListingText(text) {
  let q = '';
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (q === "'") { if (c === "'") q = ''; continue; }
    if (q === '"') {
      if (c === '\\') i += 1;
      else if (c === '"') q = '';
      else if (c === '$' || c === '`') return false;
      continue;
    }
    if (c === "'" || c === '"') { q = c; continue; }
    if (!PLAIN_UNQUOTED_RE.test(c)) return false;
  }
  return q === '';
}

function securityIsOnlySearchText(raw) {
  const text = String(raw || '').replace(HARMLESS_REDIRECT_RE, ' ');
  if (!plainListingText(text)) return false;
  return scanCommand(text).pipes.flat().every((st) => {
    const words = stageWords(st);
    return LISTING_HEADS.has(words[0]) && !words.some(isLongOption);
  });
}

/** A command word the scan cannot read: a variable, a glob, a command substitution. */
const unresolvedWord = (w) => typeof w === 'string' && w !== '[' && w !== '[[' && (/[$*?\[]/.test(w) || w.includes(SUBST));

/** An interpreter word that only reads data: `python3 -m json.tool`, literal `-c`/`-e` code, or a script file. */
function safeInterpreter(words, k) {
  const base = baseName(words[k]);
  if (SHELL_WORD_RE.test(base)) return words.length > k + 1 && words.slice(k + 1).every((x) => /^(?:--version|--help)$/.test(x));
  for (let i = k + 1; i < words.length; i += 1) {
    const w = words[i];
    if (/^\d*[<>]/.test(w)) { if (/^\d*[<>]+&?$/.test(w)) i += 1; continue; }
    if (/^-[a-zA-Z]*m$/.test(w)) return words[i + 1] === 'json.tool';
    if (/^-[a-zA-Z]*[ceEp]$|^--(?:eval|print)$/.test(w)) return i + 1 < words.length && !CODE_DANGER_RE.test(words[i + 1]);
    if (/^-[WXrIM]$/.test(w) || /^--(?:require|import|loader)$/.test(w)) { i += 1; continue; }
    if (w === '-' || /^\/dev\/(?:stdin|fd\/\d+)$/.test(w)) return false;
    if (w.startsWith('-')) continue;
    return true; // a script file: the piped text is its data
  }
  return false;
}

/** Does this stage run text it is given? ctx 'pipe': text arrives on stdin; 'sub': it arrives as a substitution. */
function stageRuns(stage, ctx) {
  const key = `runs_${ctx}`;
  if (stage[key] === undefined) stage[key] = stageRunsRaw(stage, ctx);
  return stage[key];
}
function stageRunsRaw(stage, ctx) {
  for (const sub of stage.subs) for (const st of subStages(sub)) if (stageRuns(st, 'pipe')) return true;
  const words = stageWords(stage);
  const h = headOf(words);
  if (h >= words.length) return false;
  if (HARMLESS_HEADS.has(baseName(words[h]))) return false;
  if (ctx === 'pipe' && unresolvedWord(words[commandWord(words)])) return true;
  const compound = words.some((w) => COMPOUND_WORDS.has(w));
  for (let k = h; k < words.length; k += 1) {
    const b = baseName(words[k]);
    if (compound && ctx === 'pipe' && (b === 'eval' || b === 'source' || b === '.')) return true;
    if (SINK_WORD_RE.test(b)) { if (!safeInterpreter(words, k)) return true; continue; }
    if (k === h && ctx === 'sub' && (b === 'eval' || b === 'source' || b === '.')) return true;
    if (ctx === 'pipe' && (b === 'source' || b === '.') && /^(?:-|\/dev\/(?:stdin|fd\/\d+))$/.test(words[k + 1] || '')) return true;
  }
  return false;
}

function stageFetches(stage) {
  if (stage.fetches === undefined) stage.fetches = stageFetchesRaw(stage);
  return stage.fetches;
}
function stageFetchesRaw(stage) {
  const words = stageWords(stage);
  const h = headOf(words);
  const head = h < words.length ? baseName(words[h]) : '';
  if (FETCH_WORDS.has(head)) return true;
  if (head === 'base64' && words.some((w) => /^-[a-zA-Z]*[dD]$|^--decode$/.test(w))) return true;
  if (!HARMLESS_HEADS.has(head) && words.some((w) => FETCH_WORDS.has(baseName(w)))) return true; // sudo curl, timeout 5 curl
  for (const sub of stage.subs) for (const st of subStages(sub)) if (stageFetches(st)) return true;
  return false;
}

function pipeToShellTree(tree, tainted = new Map()) {
  let inCompound = 0; // depth of an if/while/for opened on fetched text, until its fi/done/esac
  for (const pipe of tree.pipes) {
    let fetched = false;
    for (const st of pipe) {
      for (const sub of st.subs) if (pipeToShellTree(sub, tainted)) return true;
      const words = stageWords(st);
      const first = words[0] || '';
      if (fetched && stageRuns(st, 'pipe')) return true;
      if (fetched && COMPOUND_OPEN.has(first) && inCompound === 0) inCompound = 1;
      else if (inCompound > 0) {
        if (COMPOUND_OPEN.has(first)) inCompound += 1;
        else if (COMPOUND_CLOSE.has(first)) inCompound -= 1;
        const cw = words[commandWord(words)] || '';
        const b = baseName(cw);
        if (stageRuns(st, 'pipe') || b === 'eval' || b === 'source' || b === '.') return true;
      }
      // `eval "$(curl ...)"`, `source <(curl ...)`, `sh -c "$(curl ...)"`: a stage that runs a substitution that fetches.
      if (st.subs.some((sub) => subStages(sub).some(stageFetches)) && stageRuns(st, 'sub')) return true;
      // A variable that holds fetched text, used later as code: x=$(curl ...); eval "$x"
      const uses = (x) => [...tainted.keys()].some((n) => new RegExp(`\\$\\{?${n}\\b`).test(x));
      for (const w of words) {
        if (/^(?:export|local|declare|typeset|readonly)$/.test(w)) continue;
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(w);
        if (!m) break;
        if ((m[2].includes(SUBST) && st.subs.some((sub) => subStages(sub).some(stageFetches))) || uses(m[2])) tainted.set(m[1], true);
      }
      if (tainted.size) {
        const cwi = commandWord(words);
        const cw = words[cwi] || '';
        const b = baseName(cw);
        if (words.slice(cwi).some(uses) && (SINK_WORD_RE.test(b) || b === 'eval' || b === 'source' || b === '.' || uses(cw))) return true;
        if (words.some(uses)) fetched = true; // `echo "$x" | sh`: the variable's text goes down the pipe
      }
      if (stageFetches(st)) fetched = true;
    }
  }
  return false;
}

/** Matched on the whole command, because the pipe is what makes it dangerous. */
function pipeToShell(cmd) {
  return pipeToShellTree(scanCommand(cmd));
}

const TEMP_ROOT_RE = /^(?:\/private)?\/(?:tmp|var\/tmp|var\/folders\/[^/]+\/[^/]+\/T)(?=\/|$)/;
const TMPDIR_VAR_RE = /^\$(?:TMPDIR|TMP|TEMP|TEMPDIR)(?=\/|$)/;
const TMPDIR_STANDIN = '/private/var/folders/zz/zz/T';
const TMP_MAX_DEPTH = 32;
const PROJECT_MARKERS = ['.git', 'package.json', 'Makefile', 'configure', 'Cargo.toml', 'pyproject.toml', 'CMakeLists.txt'];
const TMP_SHELLS = /^(?:ba|z|da|k|fi|c|tc)?sh$|^(?:source|\.)$/;
const TMP_INTERPRETERS = /^(?:python[0-9.]*|node|ruby|perl|deno|bun|osascript)$/;
const TMP_OPEN_RE = /\.(?:app|pkg|dmg|command|terminal)$/i;
const unquote = (w) => String(w || '').replace(/^["']+|["']+$/g, '');
const expandTmpVar = (w) => String(w || '').replace(TMPDIR_VAR_RE, TMPDIR_STANDIN);
// Separators inside quotes are swapped for private characters so the quoted text stays one word, and swapped back
// when a `sh -c` string is read as a command of its own.
const MASK_CHARS = ';&|\n`(){}';
const maskQuoted = (t) => t.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, (m) => m.replace(/[;&|\n`(){}]/g, (c) => String.fromCharCode(0xE000 + MASK_CHARS.indexOf(c))));
const unmask = (t) => t.replace(/[-]/g, (c) => MASK_CHARS[c.charCodeAt(0) - 0xE000]);

/**
 * Is `word` a path to a program or script in a temp folder? A relative word counts only against a folder the
 * command itself `cd`'d into (`bare` words, such as the script given to an interpreter, too). The rule is on the
 * file's parent folder: a file directly in a temp root is denied; one folder down is denied unless it is a project
 * (a marker file beside it or the file is `configure`/`Makefile`); two or more folders down is allowed.
 */
function underTmp(word, cdDir, home, bare) {
  const w = expandTmpVar(unquote(word));
  if (!w || /^-/.test(w)) return false;
  const relative = /^\.\.?(?:\/|$)/.test(w) || (bare && !w.startsWith('/'));
  const abs = relative ? (cdDir ? path.resolve(cdDir, w) : '') : (w.startsWith('/') ? path.resolve(w) : '');
  const root = abs && TEMP_ROOT_RE.exec(abs);
  if (!root) return false;
  // The home folder is never a temp folder, even when a test or a sandbox puts HOME under one.
  if (home && abs.startsWith(`${home}/`)) return false;
  const parts = abs.slice(root[0].length).split('/').filter(Boolean);
  if (parts.length === 0) return false;
  if (parts.length === 1) return true;
  // One or more folders down: a project (the file is `configure`/`Makefile`, or a marker file sits in a folder above it
  // inside the temp root) may run its own programs; anything else is a payload.
  if (PROJECT_MARKERS.includes(parts[parts.length - 1])) return false;
  // A path this deep is not a real project layout; it is denied unread rather than probed level by level.
  if (parts.length > TMP_MAX_DEPTH) return true;
  try {
    let dir = root[0];
    for (let x = 0; x < parts.length - 1; x += 1) {
      dir = path.join(dir, parts[x]);
      if (PROJECT_MARKERS.some((m) => fs.existsSync(path.join(dir, m)))) return false;
    }
  } catch { /* no marker */ }
  return true;
}

/** Programs a segment runs: the program itself, a script handed to a shell or interpreter, a script on stdin, a `sh -c` string, `open` targets. */
// Per interpreter: flags that carry inline code or a module (so no file is run), and flags that take a value.
const INTERP_FLAGS = [
  [/^python/, /^-[a-zA-Z]*[cm]$/, /^-[WX]$/],
  [/^(?:node|deno|bun)$/, /^-[ep]$|^--(?:eval|print)$/, /^(?:-r|--require|--import|--loader)$/],
  [/^ruby$/, /^-e$/, /^-[Ir]$/],
  [/^perl$/, /^-[eE]$/, /^-[IM]$/],
  [/^osascript$/, /^-e$/, /^$/],
];

/** The script an interpreter or shell runs: { code: true } for inline code, { script } for a file, {} for none (stdin). */
function scriptOf(head, args) {
  const [, codeRe, valueRe] = INTERP_FLAGS.find(([re]) => re.test(head)) || [null, /^-[a-zA-Z]*c$/, /^-[oO]$/];
  for (let i = 0; i < args.length; i += 1) {
    if (codeRe.test(args[i])) return { code: i };
    if (valueRe.test(args[i])) { i += 1; continue; }
    if (/^\d*[<>]/.test(args[i])) { if (/^\d*[<>]+&?$/.test(args[i])) i += 1; continue; } // a redirect and its target
    if (args[i] === '-' || args[i].startsWith('-')) continue;
    return { script: args[i] };
  }
  return {};
}

/** Programs a segment runs: the program itself, a script handed to a shell or interpreter, a script on stdin, a `sh -c` string, `open` targets. */
function tmpExec(seg, cdDir, home, depth = 0) {
  if (underTmp(seg.exe, cdDir, home)) return true;
  const isShell = TMP_SHELLS.test(seg.head);
  if (isShell || TMP_INTERPRETERS.test(seg.head)) {
    const found = scriptOf(seg.head, seg.args);
    if (found.code !== undefined) {
      if (!isShell) return false; // inline code or a module name, not a file
      const inner = unmask(seg.args.slice(found.code + 1).join(' '));
      return depth < 4 && tmpExecIn(inner, cdDir, home, depth + 1);
    }
    if (found.script) return underTmp(found.script, cdDir, home, true);
    // No script given: `bash < /tmp/payload.sh` runs the file on stdin. A script that is only fed data
    // (`python3 parse.py < /tmp/in.json`) never reaches this line.
    for (const m of seg.text.matchAll(/(?:^|[\s\d])<\s*([^\s<>&|]+)/g)) if (underTmp(m[1], cdDir, home, true)) return true;
    return false;
  }
  if (seg.head === 'open') return seg.args.some((a) => !a.startsWith('-') && TMP_OPEN_RE.test(unquote(a)) && underTmp(a, cdDir, home));
  return false;
}

/** Runs tmpExec over each command part of `text` (quotes already removed), tracking `cd`. */
function tmpExecIn(text, startDir, home, depth) {
  let dir = startDir;
  const flat = text.replace(/\$\{(?:TMPDIR|TMP|TEMP|TEMPDIR)(?::?-[^}]*)?\}/g, '$$TMPDIR');
  for (const s of segments(flat)) {
    if (s.whole) continue;
    if (s.head === 'cd' && s.args[0]) {
      const to = expandTmpVar(s.args[0].replace(/^~(?=\/|$)/, home));
      dir = path.isAbsolute(to) ? path.resolve(to) : (dir ? path.resolve(dir, to) : null);
      continue;
    }
    if (tmpExec(s, dir, home, depth)) return true;
  }
  return false;
}

const TCC_DB_RE = /com\.apple\.TCC\/TCC\.db|\/TCC\.db\b/;
function tccTouch(seg) {
  if (seg.head === 'tccutil') return true;
  return !TEXT_ONLY(seg) && TCC_DB_RE.test(seg.text);
}

const LAUNCH_DIR_RE = /Library\/Launch(?:Agents|Daemons)\//;
const LAUNCH_WRITE_HEADS = new Set(['cp', 'mv', 'ln', 'ditto', 'rsync', 'install', 'tee', 'touch', 'curl', 'wget']);
function launchAgentChange(seg) {
  if (seg.head === 'launchctl') {
    const sub = seg.args.find((a) => !a.startsWith('-'));
    return /^(load|bootstrap|disable|enable|submit)$/.test(sub || '');
  }
  if (!LAUNCH_DIR_RE.test(seg.text) || TEXT_ONLY(seg)) return false;
  if (LAUNCH_WRITE_HEADS.has(seg.head)) return true;
  if (seg.head === 'defaults' && seg.args[0] === 'write') return true;
  if (seg.head === 'plutil' && seg.args.some((a) => /^-(replace|insert|remove|convert|create)$/.test(a))) return true;
  if (seg.head === 'sed' && seg.args.some((a) => /^-i/.test(a))) return true;
  return new RegExp(String.raw`>>?\s*\S*${LAUNCH_DIR_RE.source}`).test(seg.text);
}

// Falcon rule: deny commands that run the sensor's tool or change/remove its files, labels or processes. Text that
// only names the vendor (`rg com.crowdstrike docs/`, `git commit -m "falconctl notes"`) is allowed.
const FALCON_PATH_RE = /\/Applications\/Falcon\.app|\/Library\/Application(?:\\? |%20)Support\/CrowdStrike|\/Library\/CS(?:\/|\s|$)|\/Library\/(?:LaunchDaemons|LaunchAgents)\/com\.crowdstrike\./i;
const FALCONCTL_RE = /(?:^|[\s"'/=])falconctl(?=[\s"']|$)/i;
const FALCON_LABEL_RE = /com\.crowdstrike/i;
const FALCON_WRITE_HEADS = /^(?:rm|mv|cp|ln|sed|tee|chmod|chown|chflags|defaults|plutil|touch|truncate|unlink|rsync|ditto|install|dd|trash)$/;
const FALCON_LAUNCHCTL_SUBS = /\b(?:bootout|unload|remove|disable|kill|stop|bootstrap|load|enable|kickstart)\b/;
const FALCON_PROC_RE = /\bfalcon(?:d|ctl|-sensor|SensorMacOS|Notifications)\b/i;
function falconTouch(seg) {
  if (TEXT_ONLY(seg)) return false;
  if (seg.head === 'falconctl' || FALCONCTL_RE.test(seg.text) || FALCON_PATH_RE.test(seg.text)) return true;
  if (/\blaunchctl\b/.test(seg.text) && FALCON_LAUNCHCTL_SUBS.test(seg.text) && FALCON_LABEL_RE.test(seg.text)) return true;
  if (/^(?:kill|pkill|killall)$/.test(seg.head) && (FALCON_PROC_RE.test(seg.text) || /crowdstrike/i.test(seg.text))) return true;
  if (FALCON_WRITE_HEADS.test(seg.head) && FALCON_LABEL_RE.test(seg.text)) return true;
  return seg.head === 'systemextensionsctl' && /\buninstall\b/.test(seg.text) && /X9E956P446/i.test(seg.text);
}

// Kills and removals aimed at the sensor through another command: `kill -9 $(pgrep falcond)`,
// `pgrep falcond | xargs launchctl remove`, `P=$(pgrep falcond); kill $P`. The target of the kill or removal is what
// counts: its own arguments, a substitution inside them, text piped into an `xargs` form of it from an earlier stage,
// or a variable assigned from a lookup of the sensor in the same command. A later word (`| tee crowdstrike.log`) is
// not a target, and `rg falcond logs/` names the sensor without acting on it.
const FALCON_ACTING_LAUNCHCTL = /^(?:remove|bootout|unload|stop|kill|disable)$/;
const FALCON_NAMED_RE = /falcon|crowdstrike|\bcrowd\b/i;
const KILL_LAUNCHERS = new Set(['sudo', 'env', 'nice', 'nohup', 'time', 'command', 'exec', 'timeout', 'gtimeout', 'xargs', 'caffeinate', 'doas']);

function actingTarget(words) {
  let i = headOf(words);
  let stdinFed = false;
  while (i < words.length) {
    const b = baseName(words[i]);
    if (KILL_LAUNCHERS.has(b)) { if (b === 'xargs') stdinFed = true; i += 1; continue; }
    if (/^-/.test(words[i]) || /^\d+$/.test(words[i]) || ASSIGN_RE.test(words[i])) { i += 1; continue; }
    break;
  }
  if (i >= words.length) return null;
  const head = baseName(words[i]);
  if (/^(?:kill|pkill|killall)$/.test(head)) return { args: words.slice(i + 1), stdinFed, pattern: head !== 'kill' };
  if (head === 'systemextensionsctl') {
    const k = words.findIndex((w, x) => x > i && w === 'uninstall');
    if (k >= 0) return { args: words.slice(k + 1), stdinFed };
  }
  if (head === 'launchctl') {
    const k = words.findIndex((w, x) => x > i && !w.startsWith('-'));
    if (k >= 0 && FALCON_ACTING_LAUNCHCTL.test(words[k])) return { args: words.slice(k + 1), stdinFed };
  }
  return null;
}

const SENSOR_NAMES = ['falcond', 'falconctl', 'falcon-sensor', 'Falcon', 'CSFalconService', 'CSFalconDaemon', 'com.crowdstrike.falcon.Agent', 'crowdstrike'];
/** pkill and killall take patterns: a glob or regex that can match a sensor process name is aimed at it. */
function patternHitsSensor(args) {
  for (const a of args) {
    if (a.startsWith('-') || !/[*?[\].()|^+]/.test(a)) continue;
    const asGlob = `^${a.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`;
    for (const src of [asGlob, a]) {
      try { const re = new RegExp(src, 'i'); if (SENSOR_NAMES.some((n) => re.test(n))) return true; } catch { /* not a regex */ }
    }
  }
  return false;
}

function falconTree(tree, assigned) {
  for (const pipe of tree.pipes) {
    for (let idx = 0; idx < pipe.length; idx += 1) {
      const st = pipe[idx];
      for (const sub of st.subs) if (falconTree(sub, assigned)) return true;
      const words = stageWords(st);
      for (const w of words) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(w);
        if (!m) break;
        if (FALCON_NAMED_RE.test(m[2]) || (m[2].includes(SUBST) && FALCON_NAMED_RE.test(fullText(st)))) assigned.set(m[1], true);
      }
      const t = actingTarget(words);
      if (!t) continue;
      const subText = st.subs.map((sub) => subStages(sub).map(fullText).join(' ')).join(' ');
      if (FALCON_NAMED_RE.test(`${t.args.join(' ')} ${subText}`)) return true;
      if (t.pattern && patternHitsSensor(t.args)) return true;
      if (t.stdinFed && pipe.slice(0, idx).some((x) => FALCON_NAMED_RE.test(fullText(x)))) return true;
      if (t.args.some((a) => [...assigned.keys()].some((name) => new RegExp(`\\$\\{?${name}\\b`).test(a)))) return true;
    }
  }
  return false;
}

function falconChain(raw) {
  return falconTree(scanCommand(raw), new Map());
}

function quarantineStrip(seg) {
  if (TEXT_ONLY(seg)) return false;
  for (const m of seg.text.matchAll(XATTR_RE)) {
    const args = m[1].trim().split(/\s+/);
    const flags = args.filter((a) => /^-[a-zA-Z]+$/.test(a)).join('');
    if (/c/.test(flags) || (/d/.test(flags) && args.includes('com.apple.quarantine'))) return true;
  }
  return false;
}

function launchctlSecret(seg) {
  if (TEXT_ONLY(seg)) return false;
  for (const m of seg.text.matchAll(LAUNCHCTL_SETENV_RE)) {
    const words = m[1].trim().split(/\s+/);
    for (let k = 0; k < words.length; k += 2) if (SECRET_NAME_RE.test(words[k])) return true;
  }
  return false;
}

// ---------------------------------------------------------------- shell parsing for the newer rules
//
// The newer rules (net-oneliner, curl-upload, recorder, banned-agent) read the raw command, before normalize()
// strips its quotes. shellParse keeps quoted strings as one word and keeps heredoc bodies as the command's stdin
// instead of splitting them into commands. So `git commit -m "exec 3<>/dev/tcp/x"` stays one word, and a commit
// message written through `$(cat <<'EOF' ... EOF)` is never read as commands.

/** Index just past the `)` that closes a `$(` whose body starts at i; skips quotes and heredoc bodies. */
function substEnd(s, i) {
  let depth = 1;
  const pending = [];
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') { i += 2; continue; }
    if (c === "'") { const e = s.indexOf("'", i + 1); i = e < 0 ? s.length : e + 1; continue; }
    if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (c === '<' && s[i + 1] === '<' && s[i + 2] !== '<') {
      const m = s.slice(i).match(/^<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/);
      if (m) { pending.push(m[2]); i += m[0].length; continue; }
    }
    if (c === '\n' && pending.length) {
      i += 1;
      while (pending.length) {
        const delim = pending.shift();
        while (i < s.length) {
          let nl = s.indexOf('\n', i);
          if (nl < 0) nl = s.length;
          const line = s.slice(i, nl).replace(/^\t+/, '');
          i = nl + 1;
          if (line === delim) break;
        }
      }
      continue;
    }
    if (c === '(') depth += 1;
    if (c === ')') { depth -= 1; if (depth === 0) return i + 1; }
    i += 1;
  }
  return s.length;
}

function shellParse(src, depth = 0) {
  const s = String(src || '');
  const cmds = [];
  const newCmd = (pipedFrom = null) => ({ words: [], redirects: [], stdin: null, herestring: null, pipedFrom, substs: [] });
  let cur = newCmd();
  let word = null;
  let pendingRedirect = null;
  let pendingHeredoc = null;
  const heredocs = [];
  const endWord = () => {
    if (word === null) return;
    if (pendingRedirect) {
      cur.redirects.push({ op: pendingRedirect, target: word });
      if (pendingRedirect === '<<<') cur.herestring = word;
      pendingRedirect = null;
    } else if (pendingHeredoc) {
      heredocs.push({ delim: word, strip: pendingHeredoc === '<<-', cmd: cur });
      pendingHeredoc = null;
    } else cur.words.push(word);
    word = null;
  };
  const endCmd = (piped) => {
    endWord();
    const prev = cur;
    if (prev.words.length || prev.redirects.length || prev.stdin !== null) cmds.push(prev);
    cur = newCmd(piped ? prev : null);
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\n') {
      endCmd(false);
      i += 1;
      // Heredoc bodies start on the next line and end at the delimiter line.
      while (heredocs.length) {
        const h = heredocs.shift();
        const lines = [];
        while (i < s.length) {
          let nl = s.indexOf('\n', i);
          if (nl < 0) nl = s.length;
          const line = s.slice(i, nl);
          i = nl + 1;
          if ((h.strip ? line.replace(/^\t+/, '') : line) === h.delim) break;
          lines.push(line);
        }
        const body = lines.join('\n');
        h.cmd.stdin = h.cmd.stdin === null ? body : `${h.cmd.stdin}\n${body}`;
        if (!cmds.includes(h.cmd)) cmds.push(h.cmd);
      }
      continue;
    }
    if (c === ' ' || c === '\t') { endWord(); i += 1; continue; }
    if (c === '#' && word === null) { while (i < s.length && s[i] !== '\n') i += 1; continue; }
    if (c === '\\') {
      if (s[i + 1] === '\n') { i += 2; continue; }
      word = (word || '') + (s[i + 1] || '');
      i += 2;
      continue;
    }
    if (c === "'") {
      const end = s.indexOf("'", i + 1);
      const stop = end < 0 ? s.length : end;
      word = (word || '') + s.slice(i + 1, stop);
      i = stop + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let buf = '';
      while (j < s.length && s[j] !== '"') {
        if (s[j] === '\\' && /["\\$`\n]/.test(s[j + 1] || '')) { if (s[j + 1] !== '\n') buf += s[j + 1]; j += 2; continue; }
        if (s[j] === '$' && s[j + 1] === '(') {
          // "$(cat <<'EOF' ... EOF)": the substitution, quotes and heredoc included, stays part of this word, and
          // its body is parsed as commands of its own at the end (so "$(python3 -c ...)" is still seen).
          const end = substEnd(s, j + 2);
          buf += s.slice(j, end);
          cur.substs.push(s.slice(j + 2, end - 1));
          j = end;
          continue;
        }
        if (s[j] === '`') {
          const end = s.indexOf('`', j + 1);
          const stop = end < 0 ? s.length : end;
          cur.substs.push(s.slice(j + 1, stop));
          buf += s.slice(j, stop + 1);
          j = stop + 1;
          continue;
        }
        buf += s[j];
        j += 1;
      }
      word = (word || '') + buf;
      i = j + 1;
      continue;
    }
    if (c === ';' || c === '`' || c === ')' || c === '{' || c === '}') {
      // { and } only as their own word: `{ cmd; }`. Inside a word (${HOME}, a{b}) they are text.
      if ((c === '{' || c === '}') && (word !== null || !/[\s;]|^$/.test(s[i + 1] || ''))) { word = (word || '') + c; i += 1; continue; }
      endCmd(false);
      i += c === ';' && s[i + 1] === ';' ? 2 : 1;
      continue;
    }
    if (c === '(') {
      if (word !== null && /[$<>]$/.test(word)) word = word.slice(0, -1) || null; // $( <( >(
      endCmd(false);
      i += 1;
      continue;
    }
    if (c === '|') {
      if (s[i + 1] === '|') { endCmd(false); i += 2; continue; }
      endCmd(true);
      i += s[i + 1] === '&' ? 2 : 1;
      continue;
    }
    if (c === '&') {
      if (s[i + 1] === '&') { endCmd(false); i += 2; continue; }
      if (s[i + 1] === '>') { endWord(); pendingRedirect = s[i + 2] === '>' ? '&>>' : '&>'; i += pendingRedirect.length; continue; }
      endCmd(false);
      i += 1;
      continue;
    }
    if (c === '<' || c === '>') {
      if (c === '<' && s[i + 1] === '(') { endCmd(false); i += 2; continue; }
      if (c === '>' && s[i + 1] === '(') { endCmd(false); i += 2; continue; }
      if (word !== null && /^\d+$/.test(word)) word = null; // fd number: 2> 3<>
      endWord();
      const op = (s.slice(i).match(/^(<<<|<<-|<<|<>|<&|>>|>\||>&|<|>)/) || ['<'])[0];
      i += op.length;
      if (op === '<<' || op === '<<-') pendingHeredoc = op;
      else pendingRedirect = op;
      continue;
    }
    word = (word || '') + c;
    i += 1;
  }
  endCmd(false);
  if (depth < 3) {
    for (const cmd of [...cmds]) for (const body of cmd.substs) cmds.push(...shellParse(body, depth + 1));
  }
  return cmds;
}

/** Index of the program word, after launchers, variable assignments and their options. */
const PROGRAM_INDEX_MEMO = new WeakMap();
function programIndex(words) {
  if (!Array.isArray(words)) return programIndexRaw(words);
  let k = PROGRAM_INDEX_MEMO.get(words);
  if (k === undefined) { k = programIndexRaw(words); PROGRAM_INDEX_MEMO.set(words, k); }
  return k;
}
function programIndexRaw(words) {
  let i = 0;
  while (i < words.length) {
    const w = words[i];
    if (LAUNCHERS.has(path.basename(w)) || w === '{' || w === '}' || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i += 1; continue; }
    const prev = i > 0 ? path.basename(words[i - 1]) : '';
    if (i > 0 && LAUNCHERS.has(prev) && /^-/.test(w)) {
      i += /^-[ugnCDhpTUa]$/.test(w) ? 2 : 1; // sudo -u user, nice -n 10, exec -a name
      continue;
    }
    if (/^(timeout|gtimeout)$/.test(prev) && /^\d/.test(w)) { i += 1; continue; }
    break;
  }
  return i;
}

// `mac-yolo-credential-guard check -- <cmd>` (or `node .../mac-yolo-credential-guard.js check ...`) only evaluates
// its argument. The guard must be the program, or the interpreter's script, and `check` the next word.
const GUARD_CHECK = (words) => {
  const k = programIndex(words);
  const isGuard = (w) => [MARKER, `${MARKER}.js`].includes(path.basename(w || ''));
  if (isGuard(words[k])) return words[k + 1] === 'check';
  return /^(node|nodejs)$/.test(path.basename(words[k] || '')) && isGuard(words[k + 1]) && words[k + 2] === 'check';
};

function textOnlyCmd(cmd) {
  const k = programIndex(cmd.words);
  const head = cmd.words[k] ? path.basename(cmd.words[k]) : '';
  const args = cmd.words.slice(k + 1);
  if (!head) return true;
  if (head === 'but' && /^(commit|describe|reword)$/.test(args.find((a) => !a.startsWith('-')) || '')) return true;
  return TEXT_ONLY({ head, args }) || GUARD_CHECK(cmd.words);
}

const LANG_OF = (b) => (/^python[0-9.]*$/.test(b) ? 'py' : /^(node|nodejs)$/.test(b) ? 'js' : b === 'deno' ? 'deno' : b === 'bun' ? 'bun'
  : /^perl[0-9.]*$/.test(b) ? 'pl' : /^ruby[0-9.]*$/.test(b) ? 'rb' : /^(sh|bash|zsh|dash|ksh)$/.test(b) ? 'sh' : b === 'eval' ? 'eval' : null);

/** The inline code an option word carries (with `next` as its value), or null. */
function codeFlag(lang, a, next) {
  if (typeof a !== 'string' || a.startsWith('--') && !/^--(eval|print)(=|$)/.test(a)) return null;
  const val = next ?? '';
  if (lang === 'py') {
    if (/^-[A-Za-z]*c$/.test(a)) return val;
    const m = a.match(/^-[bBdEhiIOPqsSuvVx]*c([\s\S]+)$/);
    return m ? m[1] : null;
  }
  if (lang === 'js' || lang === 'bun') {
    if (/^(-e|--eval|-p|--print|-pe|-ep)$/.test(a)) return val;
    const m = a.match(/^--(?:eval|print)=([\s\S]*)$/);
    return m ? m[1] : null;
  }
  if (lang === 'pl') {
    if (/^-[a-zA-Z0-9]*[eE]$/.test(a)) return val;
    const m = a.match(/^-[lnpaws]*[eE]([\s\S]+)$/);
    return m ? m[1] : null;
  }
  if (lang === 'rb') {
    if (a === '-e') return val;
    const m = a.match(/^-e([\s\S]+)$/);
    return m ? m[1] : null;
  }
  if (lang === 'sh') return /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a) ? val : null;
  return null;
}

/**
 * The inline code a command runs: [{lang, code, mods, script}]. `script` is the file an interpreter runs instead
 * (python3 x.py), for the recorder and banned-agent rules.
 */
function inlineCode(cmd) {
  const out = [];
  const w = cmd.words;
  const fromStdin = () => {
    if (cmd.stdin !== null) return cmd.stdin;
    if (cmd.herestring !== null) return cmd.herestring;
    const p = cmd.pipedFrom;
    if (p) {
      const k = programIndex(p.words);
      // printf and echo -e turn \n and \t into real ones; decoding always is the stricter reading.
      if (/^(echo|printf)$/.test(path.basename(p.words[k] || ''))) {
        return p.words.slice(k + 1).filter((x) => !/^-[neE]+$/.test(x)).join(' ').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
      }
      if (p.stdin !== null && path.basename(p.words[k] || '') === 'cat') return p.stdin;
    }
    return null;
  };
  for (let k = programIndex(w); k < w.length; k += 1) {
    const lang = LANG_OF(path.basename(w[k]));
    if (!lang) continue;
    const args = w.slice(k + 1);
    const res = { lang, code: null, mods: [], script: null };
    if (lang === 'eval') { res.code = args.join(' '); out.push(res); break; }
    if (lang === 'deno') { if (args[0] === 'eval') res.code = args.slice(1).find((a) => !a.startsWith('-')) ?? null; else res.script = args.find((a) => !a.startsWith('-') && a !== 'run') || null; out.push(res); break; }
    let j = 0;
    let bare = true;
    while (j < args.length) {
      const a = args[j];
      if (lang === 'py') {
        if (/^-[bBdEhiIOPqsSuvVx]*c$/.test(a)) { res.code = args[j + 1] ?? ''; break; }
        const att = a.match(/^-[bBdEhiIOPqsSuvVx]*c([\s\S]+)$/);
        if (att && !a.startsWith('--')) { res.code = att[1]; break; }
        if (/^-[WXQ]$/.test(a)) { j += 2; continue; }
        if (a === '-m') { bare = false; break; }
        if (a === '-') break;
        if (a.startsWith('-')) { j += 1; continue; }
        res.script = a; bare = false; break;
      }
      if (lang === 'js' || lang === 'bun') {
        if (/^(-e|--eval|-p|--print|-pe|-ep)$/.test(a)) { res.code = args[j + 1] ?? ''; break; }
        const eq = a.match(/^--(?:eval|print)=([\s\S]*)$/);
        if (eq) { res.code = eq[1]; break; }
        if (/^(-r|--require|--import|--loader|--input-type|-C|--conditions)$/.test(a)) { j += 2; continue; }
        if (a === '-') break;
        if (a.startsWith('-')) { j += 1; continue; }
        if (lang === 'bun' && /^(run|x|install|add|i|test|build)$/.test(a)) { bare = false; res.script = args[j + 1] || null; break; }
        res.script = a; bare = false; break;
      }
      if (lang === 'pl') {
        const m = a.match(/^-M-?([\w:]+)/);
        if (m) { res.mods.push(m[1]); j += 1; continue; }
        if (/^-[a-zA-Z0-9]*[eE]$/.test(a)) { res.code = args[j + 1] ?? ''; break; }
        const att = a.match(/^-[lnpaws]*[eE]([\s\S]+)$/);
        if (att) { res.code = att[1]; break; }
        if (a.startsWith('-')) { j += 1; continue; }
        res.script = a; bare = false; break;
      }
      if (lang === 'rb') {
        if (a === '-r') { res.mods.push(args[j + 1] || ''); j += 2; continue; }
        const r = a.match(/^-r(.+)$/);
        if (r) { res.mods.push(r[1]); j += 1; continue; }
        if (a === '-e') { res.code = args[j + 1] ?? ''; break; }
        const att = a.match(/^-e([\s\S]+)$/);
        if (att) { res.code = att[1]; break; }
        if (a.startsWith('-')) { j += 1; continue; }
        res.script = a; bare = false; break;
      }
      if (lang === 'sh') {
        if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a) && !a.startsWith('--')) { res.code = args[j + 1] ?? ''; break; }
        if (/^-o$/.test(a)) { j += 2; continue; }
        if (a.startsWith('-') || a.startsWith('+')) { j += 1; continue; }
        res.script = a; bare = false; break;
      }
      j += 1;
    }
    // Second pass: an option that takes a value (`node --title x -e`, `perl -I lib -e`) can make its value look
    // like the script. Inline code anywhere in the arguments still counts.
    if (res.code === null) {
      for (let q = 0; q < args.length && res.code === null; q += 1) {
        const a = args[q];
        if (lang === 'pl') { const m = a.match(/^-M-?([\w:]+)/); if (m && !res.mods.includes(m[1])) res.mods.push(m[1]); }
        if (lang === 'rb') { const m = a.match(/^-r(.+)$/); if (m) res.mods.push(m[1]); else if (a === '-r') res.mods.push(args[q + 1] || ''); }
        res.code = codeFlag(lang, a, args[q + 1]);
      }
    }
    if (res.code === null && bare) res.code = fromStdin();
    if (res.code !== null || res.script || res.mods.length) out.push(res);
    break; // one interpreter per command: `python3 x.py node -e` is python running x.py
  }
  return out;
}

const NET_MODS_JS = '(?:node:)?(?:net|http|https|http2|tls|dgram)';
const NET_CODE = {
  py: [
    /(?<![\w.])socket\s*\.\s*(socket|create_connection|create_server)\s*\(/,
    /\bfrom\s+socket\s+import\b[\s\S]*?(?<![\w.])(socket|create_connection|create_server)\s*\(/,
    /\burlopen\s*\(/, /\burlretrieve\s*\(/, /\burllib\.request\.\w+\s*\(/, /\burllib2\.\w+\s*\(/,
    /(?<![\w.])requests\s*\.\s*(get|post|put|patch|delete|head|options|request|Session)\s*\(/,
    /(?<![\w.])httpx\s*\.\s*\w+\s*\(/, /(?<![\w.])urllib3\s*\.\s*\w+\s*\(/, /\bHTTPS?Connection\s*\(/,
    /\baiohttp\s*\.\s*ClientSession\s*\(/,
    /__import__\(\s*['"](socket|requests|urllib\.request|http\.client|httpx)['"]\s*\)\s*\.\s*\w+/,
    /\bfrom\s+(requests|httpx)\s+import\b[\s\S]*?(?<![\w.])(get|post|put|patch|delete|head|request|Session|Client)\s*\(/,
  ],
  js: [
    // Named, not only called: `const f=fetch; f(url)`. `git fetch` inside an exec string doesn't count.
    /(?<![\w.$'"`])(?<!git\s+)fetch\b(?!['"`])/, /(?<![\w.$'"`])WebSocket\b(?!['"`])/, /\b(Deno|Bun)\.(connect|connectTls|listen)\s*\(/,
    {
      // A network module loaded and then used: a dotted call, `new (x.Socket)()`, or a destructured call.
      test: (code) => new RegExp(`(require\\s*\\(|import\\s*\\(|\\bfrom)\\s*['"\`]${NET_MODS_JS}['"\`]`).test(code)
        && (/\.\s*(get|request|connect|createConnection|createSocket|createServer|Socket)\s*[()]/.test(code)
          || /\{[^}]*\b(get|request|connect|createConnection|createSocket|createServer|Socket)\b[^}]*\}/.test(code)),
    },
  ],
  pl: [
    { test: (code, mods) => (/\b(IO::Socket|LWP|HTTP::Tiny|use\s+Socket)\b/.test(code) || mods.some((m) => /^(IO::Socket|Socket|LWP|HTTP::Tiny)/.test(m)))
      && /(->\s*new\b|\bget(store)?\s*\(|\bsocket\s*\(|\bconnect\s*\()/.test(code) },
  ],
  rb: [/\b(TCPSocket|UDPSocket)\s*\.\s*(new|open)\b/, /\bSocket\s*\.\s*tcp\b/, /\bNet::HTTP\s*(\.\s*\w+|::\w+\s*\.\s*new)\b/, /\bURI\s*\.\s*open\b/],
};
NET_CODE.deno = NET_CODE.js;
NET_CODE.bun = NET_CODE.js;

const DEV_NET_RE = /^\/dev\/(tcp|udp)\//;

/** `import socket as s; s.socket()` -> `socket.socket()`, so aliases don't hide a call. */
function pythonUnalias(code) {
  let out = String(code);
  for (const m of out.matchAll(/\bimport\s+([\w.]+)\s+as\s+(\w+)/g)) {
    out = out.replace(new RegExp(`(?<![\\w.])${m[2]}\\s*\\.`, 'g'), `${m[1]}.`);
  }
  for (const m of out.matchAll(/\bfrom\s+([\w.]+)\s+import\s+(\w+)\s+as\s+(\w+)/g)) {
    out = out.replace(new RegExp(`(?<![\\w.])${m[3]}\\s*\\(`, 'g'), `${m[1]}.${m[2]}(`);
  }
  return out;
}

/** True when the parsed commands run inline code that makes a network call. */
function netInParsed(cmds, depth = 0) {
  for (const cmd of cmds) {
    if (cmd.redirects.some((r) => DEV_NET_RE.test(r.target))) return true;
    if (textOnlyCmd(cmd)) continue;
    for (const ic of inlineCode(cmd)) {
      if (ic.code === null) continue;
      if (ic.lang === 'sh' || ic.lang === 'eval') {
        if (depth < 3 && netInParsed(shellParse(ic.code), depth + 1)) return true;
        continue;
      }
      const code = ic.lang === 'py' ? pythonUnalias(ic.code) : ic.code;
      if ((NET_CODE[ic.lang] || []).some((p) => p.test(code, ic.mods))) return true;
    }
  }
  return false;
}

// curl and wget options that take a value, so the value is never read as the host.
const CURL_VALUE_LONG = new Set(['--data', '--data-binary', '--data-raw', '--data-ascii', '--data-urlencode', '--json', '--form',
  '--form-string', '--upload-file', '--header', '--request', '--output', '--user', '--user-agent', '--referer', '--cookie',
  '--cookie-jar', '--proxy', '--url', '--write-out', '--max-time', '--connect-timeout', '--config', '--range', '--cert', '--key',
  '--cacert', '--resolve', '--continue-at', '--retry', '--limit-rate', '--quote', '--interface', '--oauth2-bearer', '--proxy-user',
  '--max-filesize', '--retry-delay', '--retry-max-time', '--output-dir', '--dns-servers', '--cert-type', '--key-type', '--capath']);
const CURL_VALUE_SHORT = 'dFTHXouAebcxwmKrECYyzPQU';
const WGET_VALUE = new Set(['-O', '--output-document', '-o', '--output-file', '--post-data', '--post-file', '--body-file', '--body-data',
  '--header', '-U', '--user-agent', '-P', '--directory-prefix', '--method', '-e', '--execute', '-a', '--append-output', '-i', '--input-file']);

function hostIsOrSubdomain(hostname, host) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  const root = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h || !root) return false;
  return h === root || h.endsWith(`.${root}`);
}

function hostOfWord(w) {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(w) ? w : (/^[\w.-]+\.[a-z]{2,}(:\d+)?(\/|$)/i.test(w) || /^localhost(:\d+)?(\/|$)/.test(w) ? `http://${w}` : '');
  if (!withScheme) return '';
  try { return new URL(withScheme).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return ''; }
}

/** Reads one curl or wget call. Returns { upload, hosts, output } (output: the file it writes, if any). */
function readTransfer(tool, args) {
  let upload = false;
  const hosts = [];
  let output = null;
  const seeValue = (flag, value) => {
    if (value === undefined) return;
    if (/^(-d|--data|--data-binary|--data-ascii|--json)$/.test(flag) && value.startsWith('@')) upload = true;
    if (flag === '--data-urlencode' && /^@|^[^=@]+@/.test(value)) upload = true;
    if (/^(-F|--form)$/.test(flag) && /=[@<]/.test(value)) upload = true;
    if (/^(-T|--upload-file|--post-file|--body-file)$/.test(flag)) upload = true;
    if (flag === '--url') { const h = hostOfWord(value); if (h) hosts.push(h); }
    if (/^(-o|--output|-O|--output-document)$/.test(flag) && !(tool === 'wget' && flag === '-o')) output = value;
  };
  for (let j = 0; j < args.length; j += 1) {
    const a = args[j];
    if (a.startsWith('--')) {
      const [flag, inline] = a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
      const takes = tool === 'curl' ? CURL_VALUE_LONG.has(flag) : WGET_VALUE.has(flag);
      if (!takes) continue;
      if (inline !== undefined) seeValue(flag, inline);
      else { seeValue(flag, args[j + 1]); j += 1; }
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      if (tool === 'wget') {
        if (WGET_VALUE.has(a)) { seeValue(a, args[j + 1]); j += 1; }
        else if (/^-O./.test(a)) seeValue('-O', a.slice(2));
        continue;
      }
      for (let p = 1; p < a.length; p += 1) {
        if (!CURL_VALUE_SHORT.includes(a[p])) continue;
        const rest = a.slice(p + 1);
        if (rest) seeValue(`-${a[p]}`, rest);
        else { seeValue(`-${a[p]}`, args[j + 1]); j += 1; }
        break;
      }
      continue;
    }
    const h = hostOfWord(a);
    if (h) hosts.push(h);
  }
  return { upload, hosts, output };
}

function eachSubCommand(cmds, fn, depth = 0) {
  for (const cmd of cmds) {
    if (textOnlyCmd(cmd)) continue;
    if (fn(cmd, depth)) return true;
    if (depth >= 3) continue;
    for (const ic of inlineCode(cmd)) {
      if ((ic.lang === 'sh' || ic.lang === 'eval') && ic.code && eachSubCommand(shellParse(ic.code), fn, depth + 1)) return true;
    }
  }
  return false;
}

function uploadInParsed(cmds, allowlist) {
  return eachSubCommand(cmds, (cmd) => {
    const k = cmd.words.findIndex((w, idx) => idx >= programIndex(cmd.words) && /^(curl|wget)$/.test(path.basename(w)));
    if (k < 0) return false;
    const t = readTransfer(path.basename(cmd.words[k]), cmd.words.slice(k + 1));
    if (!t.upload) return false;
    return t.hosts.length === 0 || t.hosts.some((h) => !allowlist.some((root) => hostIsOrSubdomain(h, root)));
  });
}

const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const nameWordRe = (name) => new RegExp(`(^|[^a-z0-9])${escapeRe(name)}([^a-z0-9]|$)`, 'i');
const INSTALL_WORD_RE = /(^|[^a-z])(?<!un)(install|setup|bootstrap)/i;
const RUNNER_HEADS = new Set(['npx', 'bunx', 'pnpx', 'uvx']);
const RUNNER_SUBS = { pnpm: 'dlx', yarn: 'dlx', npm: 'exec' };
const INSTALL_HEADS = new Set(['brew', 'npm', 'pnpm', 'yarn', 'bun', 'pip', 'pip3', 'pipx', 'cargo', 'gem', 'port', 'mas', 'uv']);
const SHELL_OR_INTERP = (b) => !!LANG_OF(b);

/** The program a package runner starts: npx @scope/name@1.2 -> name. */
function runnerTarget(words, k) {
  const head = path.basename(words[k]);
  let rest = words.slice(k + 1);
  if (RUNNER_SUBS[head]) { if (rest[0] !== RUNNER_SUBS[head]) return null; rest = rest.slice(1); }
  else if (!RUNNER_HEADS.has(head)) return null;
  const pkg = rest.find((a) => !a.startsWith('-'));
  if (!pkg) return null;
  return pkg.replace(/(.)@[^/]*$/, '$1').split('/').pop();
}

function openAppTarget(words, k) {
  if (path.basename(words[k]) !== 'open') return [];
  const out = [];
  for (let j = k + 1; j < words.length; j += 1) {
    if (words[j] === '-a' || words[j] === '-b') { out.push(words[j + 1] || ''); j += 1; } else if (!words[j].startsWith('-')) out.push(words[j]);
  }
  return out.map((x) => path.basename(x).replace(/\.app$/i, ''));
}

function recorderInParsed(cmds, names) {
  if (!names.length) return false;
  const res = names.map(nameWordRe);
  const mentions = (w) => res.some((r) => r.test(w));
  const isLaunch = (w) => {
    const b = path.basename(w).replace(/\.(app|js|mjs|cjs|sh|py)$/i, '').toLowerCase();
    return names.some((nm) => b === nm || b.startsWith(`${nm}-`)) || (/\.app\/Contents\/MacOS\//.test(w) && mentions(w));
  };
  const anyShell = (list) => list.some((c) => { const k = programIndex(c.words); return c.words[k] && SHELL_OR_INTERP(path.basename(c.words[k])); });
  const walk = (list, shellAround, depth) => {
    const shellHere = shellAround || anyShell(list);
    for (const cmd of list) {
      if (textOnlyCmd(cmd)) continue;
      const w = cmd.words;
      const k = programIndex(w);
      if (!w[k]) continue;
      const head = path.basename(w[k]);
      const args = w.slice(k + 1);
      if (isLaunch(w[k])) return true;
      const scriptHit = (p) => p && mentions(path.basename(p)) && INSTALL_WORD_RE.test(path.basename(p));
      if (scriptHit(w[k]) && w[k].includes('/')) return true;
      const runner = runnerTarget(w, k);
      if (runner && isLaunch(runner)) return true;
      if (openAppTarget(w, k).some((t) => isLaunch(t))) return true;
      if (INSTALL_HEADS.has(head)) {
        const subs = args.filter((a) => !a.startsWith('-'));
        const at = subs.findIndex((a) => /^(install|reinstall|add|i|upgrade)$/.test(a));
        if (at >= 0 && subs.slice(at + 1).some(mentions)) return true;
      }
      if (head === 'launchctl' && /^(load|bootstrap|kickstart|start|enable|submit)$/.test(args.find((a) => !a.startsWith('-')) || '') && args.some(mentions)) return true;
      if (/^(curl|wget)$/.test(head) && shellHere && args.some((a) => hostOfWord(a) && mentions(a))) return true;
      for (const ic of inlineCode(cmd)) {
        if (scriptHit(ic.script)) return true;
        if ((ic.lang === 'sh' || ic.lang === 'eval') && ic.code && depth < 3 && walk(shellParse(ic.code), true, depth + 1)) return true;
      }
    }
    return false;
  };
  return walk(cmds, false, 0);
}

function bannedInParsed(cmds, names) {
  if (!names.length) return false;
  const bn = (w) => path.basename(String(w || '')).replace(/\.(js|mjs|cjs|sh|py|app)$/i, '').toLowerCase();
  // `/Applications/X.app/Contents/MacOS/Electron` runs X: the bundle name counts too.
  const bundle = (w) => { const m = String(w || '').match(/([^/]+)\.app\/Contents\/MacOS\//i); return m ? m[1].toLowerCase() : null; };
  const banned = (w) => names.includes(bn(w)) || names.includes(bundle(w));
  return eachSubCommand(cmds, (cmd) => {
    const w = cmd.words;
    const k = programIndex(w);
    if (!w[k]) return false;
    if (banned(w[k])) return true;
    const runner = runnerTarget(w, k);
    if (runner && banned(runner)) return true;
    if (openAppTarget(w, k).some(banned)) return true;
    return inlineCode(cmd).some((ic) => ic.script && banned(ic.script));
  });
}

/** Parsed commands for the newer rules. A Codex argv array is used as given, not re-split. */
function parsedCommands(payload) {
  const input = payload.tool_input || payload.toolInput || {};
  let c = input.command ?? input.cmd ?? input.CommandLine;
  if (c === undefined && typeof payload.command === 'string') c = payload.command;
  if (Array.isArray(c)) return [{ words: c.map(String), redirects: [], stdin: null, herestring: null, pipedFrom: null, substs: [] }];
  return typeof c === 'string' ? shellParse(c) : [];
}

// Hook commands an edit adds to an agent hook file: the edit is applied to the current text in memory, both
// versions are parsed, and only commands that were not there before are returned.
function hookCommandsIn(text) {
  let cfg;
  try { cfg = JSON.parse(text); } catch { return null; }
  const out = [];
  const visit = (v, key) => {
    if (typeof v === 'string') { if (key === 'command') out.push(v); return; }
    if (Array.isArray(v)) { v.forEach((x) => visit(x, key)); return; }
    if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) visit(x, k);
  };
  visit(cfg?.hooks, '');
  return out;
}

function editedText(toolName, input, current) {
  if (typeof input.content === 'string' && /^(Write|write_file|write_to_file)$/i.test(toolName)) return input.content;
  const edits = Array.isArray(input.edits) ? input.edits : (typeof input.old_string === 'string' ? [input] : []);
  if (!edits.length) return typeof input.content === 'string' ? input.content : null;
  let text = current;
  for (const e of edits) {
    if (!e || typeof e !== 'object' || typeof e.old_string !== 'string' || typeof e.new_string !== 'string') return null;
    text = e.replace_all ? text.split(e.old_string).join(e.new_string) : text.replace(e.old_string, () => e.new_string);
  }
  return text;
}

function addedHookCommands(toolName, input, file) {
  if (typeof input.patch === 'string' || typeof input.input === 'string') {
    const patch = typeof input.patch === 'string' ? input.patch : input.input;
    const added = patch.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1)).join('\n');
    return [...added.matchAll(/"command"\s*:\s*("(?:[^"\\]|\\.)*")/g)].map((m) => { try { return JSON.parse(m[1]); } catch { return ''; } });
  }
  let current = '';
  try { current = fs.readFileSync(file, 'utf8'); } catch { /* new file */ }
  const next = editedText(toolName, input, current);
  if (next === null) return [];
  const after = hookCommandsIn(next);
  if (after === null) {
    return [...next.matchAll(/"command"\s*:\s*("(?:[^"\\]|\\.)*")/g)].map((m) => { try { return JSON.parse(m[1]); } catch { return ''; } });
  }
  const before = new Set(hookCommandsIn(current) || []);
  return after.filter((c) => !before.has(c));
}

// Guard settings: reads (doctor, check, grep, cat, jq) pass; writes are refused. A write is the guard's own
// install / uninstall / fix / work-folders change, a shell write whose target is a guarded path (resolved through
// any `cd` earlier in the same command), or an edit that takes the guard's entry out of an agent's hook file.
const GUARD_WRITE_SUBS = new Set(['install', 'uninstall', 'fix', 'approve', 'deny']);
const DESTRUCTIVE_HEADS = new Set(['rm', 'rmdir', 'mv', 'ln', 'chmod', 'chflags', 'chown', 'truncate', 'unlink', 'trash', 'shred']);
const COPY_HEADS = new Set(['cp', 'ditto', 'rsync', 'install', 'scp']);

function guardCall(seg) {
  const words = [seg.head, ...seg.args];
  const i = words.findIndex((w) => path.basename(w) === MARKER || path.basename(w) === `${MARKER}.js`);
  if (i < 0) return null;
  if (i === 0 && seg.head !== MARKER) return null; // the .js file as a program name is not a call
  if (i > 0 && !INTERPRETER_HEAD_RE.test(seg.head)) return null; // `cat .../mac-yolo-credential-guard.js` is a read
  const rest = words.slice(i + 1).filter((w) => !w.startsWith('-'));
  return { sub: rest[0] || '', action: rest[1] || '' };
}

// Read-only command parts for the config-folder backstop.
const READ_ONLY_HEADS = new Set(['cat', 'ls', 'head', 'tail', 'less', 'more', 'wc', 'stat', 'file', 'grep', 'egrep', 'rg',
  'cd', 'test', '[', 'pwd', 'echo', 'printf', 'true', 'diff', 'cmp', 'shasum', 'md5', 'realpath', 'readlink', 'dirname', 'basename']);
// The guard's folder named in a way normalize() can't resolve: `.config/mac-yolo`, `$VAR/mac-yolo`, `$(...)/mac-yolo`,
// or one of its files under a bare `mac-yolo/`. `~/work/mac-yolo` and `mac-yolo-safeguards` don't count.
const GUARD_DIR_WORD_RE = /(\.config|\$\{?\w+\}?|\))\/mac-yolo(?=[/\s"'`)]|$)|(^|[/\s"'=])mac-yolo\/(PAUSE|credential-guard\.json|work-folders)\b/;
const SAFE_REDIRECT_RE = /^(&?\d+|&-|-|\/dev\/null|\/dev\/stdout|\/dev\/stderr)$/;

function readOnlyCmd(cmd) {
  if (cmd.redirects.some((r) => /[>]/.test(r.op) && !SAFE_REDIRECT_RE.test(r.target))) return false;
  const k = programIndex(cmd.words);
  const head = cmd.words[k] ? path.basename(cmd.words[k]) : '';
  const args = cmd.words.slice(k + 1);
  if (!head) return true; // only variable assignments
  if (textOnlyCmd(cmd)) return true;
  if (head === 'jq') return !args.some((a) => a === '-i' || a === '--in-place');
  if (head === 'sed') return !args.some((a) => /^-[a-zA-Z]*i/.test(a) || a.startsWith('--in-place'));
  if (READ_ONLY_HEADS.has(head)) return true;
  const call = guardCall({ head, args });
  return !!call && /^(doctor|check|help|)$/.test(call.sub);
}

/** True when a command names the guard's folder and does more than read. */
function guardFolderBackstop(ctx, rawCmd) {
  if (typeof rawCmd !== 'string' || !rawCmd) return false;
  const dir = configDir(ctx);
  const cmds = shellParse(rawCmd);
  const commitText = (c) => { const k = programIndex(c.words); return /^(git|gh|but)$/.test(path.basename(c.words[k] || '')) && textOnlyCmd(c); };
  const parent = path.dirname(dir);
  const norm = (w) => normalize(w, ctx.home).replace(/\/+$/, '');
  // A glob or variable in the part under ~/.config (`~/.config/mac-yol?`, `.config/${d}lo`) may expand to the folder.
  const wild = (w) => /\.config\/[^\s]*[*?[$]/.test(w) || (norm(w).startsWith(`${parent}/`) && /[*?[$]/.test(norm(w).slice(parent.length)));
  const mentions = (w) => GUARD_DIR_WORD_RE.test(w) || norm(w).includes(dir) || wild(w);
  // `cd ~/.config && mv x mac-yolo`: after a cd into the parent, a bare mac-y* or glob word counts too.
  // After a cd into a folder above it (~), a dot-word with a glob (`.c*/mac-yolo`) counts.
  let inParent = false;
  let above = false;
  const bare = (w) => (inParent && (/^mac-y/.test(w) || /^[^/]*[*?[]/.test(w))) || (above && /^\.[^\s]*[*?[]/.test(w));
  // `find ~/.config -name x -delete`: find that changes files under a parent of the folder.
  const findWrite = (c) => {
    const k = programIndex(c.words);
    if (path.basename(c.words[k] || '') !== 'find') return false;
    const args = c.words.slice(k + 1);
    return args.some((a) => /^-(delete|exec|execdir|ok|okdir)$/.test(a))
      && args.some((a) => !a.startsWith('-') && (dir === norm(a) || dir.startsWith(`${norm(a)}/`)));
  };
  let mentioned = false;
  for (const c of cmds) {
    const k = programIndex(c.words);
    if (path.basename(c.words[k] || '') === 'cd') { const t = norm(c.words[k + 1] || '~'); inParent = t === parent || wild(c.words[k + 1] || ''); above = !inParent && parent.startsWith(`${t}/`); }
    if (findWrite(c)) return true;
    if ((!commitText(c) && c.words.some((w) => mentions(w) || bare(w))) || c.redirects.some((r) => mentions(r.target) || bare(r.target))) mentioned = true;
  }
  return mentioned && !cmds.every(readOnlyCmd);
}

/** tar or unzip that unpacks into the home folder, ~/.config or the guard folder (which hold mac-yolo/). */
function unpackOverGuard(ctx, segs, cwd) {
  let here = cwd || '';
  const resolve = (w) => (w.startsWith('/') ? w : here ? path.resolve(here, w) : '');
  for (const seg of segs) {
    if (seg.head === 'cd') { here = resolve(seg.args[0] || ctx.home) || here; continue; }
    let target = null;
    if (seg.head === 'tar' || seg.head === 'bsdtar' || seg.head === 'gtar') {
      const first = seg.args[0] || '';
      const extract = seg.args.some((a) => a === '--extract' || a === '--get' || /^-[a-zA-Z]*x/.test(a)) || /^[a-wyzA-Z]*x[a-zA-Z]*$/.test(first);
      if (!extract) continue;
      const c = seg.args.findIndex((a) => a === '-C' || a === '--directory');
      const eq = seg.args.find((a) => a.startsWith('--directory='));
      target = c >= 0 ? seg.args[c + 1] || '' : eq ? eq.slice(12) : here;
    } else if (seg.head === 'unzip' || seg.head === 'ditto') {
      if (seg.head === 'ditto' && !seg.args.some((a) => a === '-x' || a === '-xk')) continue;
      const d = seg.args.indexOf('-d');
      target = seg.head === 'unzip' ? (d >= 0 ? seg.args[d + 1] || '' : here) : seg.args.filter((a) => !a.startsWith('-')).pop() || '';
    } else continue;
    const abs = resolve(target);
    if (abs && inside(configDir(ctx), abs)) return true;
  }
  return false;
}

// Claude settings that turn every hook off, checked by value: `"disableAllHooks": false` is fine.
function hooksDisabled(text) {
  try {
    const j = JSON.parse(text);
    return !!(j && (j.disableAllHooks === true || j.allowManagedHooksOnly === true));
  } catch {
    return /"(disableAllHooks|allowManagedHooksOnly)"\s*:\s*true\b/.test(String(text || ''));
  }
}

// Codex hook trust records ([hooks.state."..."]) set to enabled = false.
function codexHooksOff(text) {
  const off = new Set();
  let section = '';
  for (const line of String(text || '').split('\n')) {
    const sec = line.match(/^\s*\[([^\]]+)\]/);
    if (sec) { section = sec[1].trim(); continue; }
    if (/^\s*enabled\s*=\s*false\b/.test(line) && /^hooks\.state\b/.test(section)) off.add(section);
    if (/^\s*hooks\s*=\s*false\b/.test(line) && section === 'features') off.add('features.hooks');
  }
  return off;
}

function guardConfigWrite(ctx, toolName, input, filePaths, segs, cmd, cwd, rawCmd) {
  const extraClaude = claudeDirs(ctx, { scanLaunchers: false }).flatMap((d) => [path.join(d, 'settings.json'), path.join(d, 'settings.local.json')]);
  const hookFileList = [...new Set([...Object.values(hookFiles(ctx)), ...extraClaude])];
  const own = [configDir(ctx), path.join(installDir(ctx), `${MARKER}.js`)];
  const guarded = [...own, ...hookFileList];
  const isGuarded = (p, destructive) => guarded.some((g) => inside(p, g) || (destructive && inside(g, p) && p !== '/'));

  if (rawCmd && guardFolderBackstop(ctx, rawCmd)) return true;
  if (cmd && unpackOverGuard(ctx, segs, cwd)) return true;

  if (isWriteTool(toolName)) {
    const abs = filePaths.map((p) => (cwd && !p.startsWith('/') ? path.resolve(cwd, p) : p));
    if (abs.some((p) => own.some((g) => inside(p, g)))) return true;
    for (const p of abs.map((x) => path.resolve(x))) {
      const settingsFile = /(^|\/)\.claude[^/]*\/settings[^/]*\.json$/.test(p);
      const codexConfig = p === path.join(ctx.home, '.codex', 'config.toml');
      if (!settingsFile && !codexConfig) continue;
      let current = '';
      try { current = fs.readFileSync(p, 'utf8'); } catch { /* new file */ }
      const next = editedText(toolName, input, current);
      const patch = typeof input.patch === 'string' ? input.patch.split('\n').filter((l) => l.startsWith('+')).map((l) => l.slice(1)).join('\n') : null;
      if (settingsFile) {
        if (next !== null && hooksDisabled(next) && !hooksDisabled(current)) return true;
        if (patch !== null && /"(disableAllHooks|allowManagedHooksOnly)"\s*:\s*true\b/.test(patch)) return true;
      } else {
        const before = codexHooksOff(current);
        if (next !== null && [...codexHooksOff(next)].some((x) => !before.has(x))) return true;
        if (patch !== null && /^\s*(enabled|hooks)\s*=\s*false\b/m.test(patch)) return true;
      }
    }
    const hookFile = abs.map((p) => path.resolve(p)).find((p) => hookFileList.includes(p));
    if (hookFile) {
      // An agent may edit its own settings; it may not take the guard out of them.
      const text = (v) => (typeof v === 'string' ? v : '');
      if (typeof input.content === 'string') {
        let current = '';
        try { current = fs.readFileSync(hookFile, 'utf8'); } catch { /* new file */ }
        if (current.includes(MARKER) && !input.content.includes(MARKER)) return true;
      }
      const edits = (Array.isArray(input.edits) ? input.edits : [input]).filter((e) => e && typeof e === 'object');
      if (edits.some((e) => text(e.old_string).includes(MARKER) && !text(e.new_string).includes(MARKER))) return true;
      if (typeof input.patch === 'string' && new RegExp(`^-.*${MARKER}`, 'm').test(input.patch)) return true;
    }
    return false;
  }
  if (!cmd) return false;

  let here = cwd || '';
  const resolve = (w) => (w.startsWith('/') ? w : here ? path.resolve(here, w) : '');
  let interpreter = false;
  let mentions = false;
  for (const seg of segs) {
    const call = guardCall(seg);
    if (call) {
      if (GUARD_WRITE_SUBS.has(call.sub)) return true;
      if (call.sub === 'work-folders' && call.action && call.action !== 'list') return true;
      continue;
    }
    if (seg.head === 'cd') { here = resolve(seg.args[0] || ctx.home) || here; continue; }
    const paths = seg.args.filter((w) => !w.startsWith('-')).map(resolve).filter(Boolean);
    if (paths.some((p) => isGuarded(p, false))) mentions = true;
    // Redirect targets: `> file`, `>> file`, `2> file` (not `2>&1`).
    for (const m of seg.text.matchAll(/(?:^|[^<>&\d])\d?>>?\s*([^\s>&]\S*)/g)) {
      const t = resolve(m[1]);
      if (t && isGuarded(t, false)) return true;
    }
    if (DESTRUCTIVE_HEADS.has(seg.head) && paths.some((p) => isGuarded(p, true))) return true;
    const inPlace = (seg.head === 'sed' && seg.args.some((w) => /^-i/.test(w) || w === '--in-place'))
      || (seg.head === 'jq' && seg.args.includes('-i')) || seg.head === 'tee';
    if (inPlace && paths.some((p) => isGuarded(p, false))) return true;
    if (COPY_HEADS.has(seg.head) && paths.length && isGuarded(paths[paths.length - 1], false)) return true;
    // Programs that write to a file named by an option: dd of=x, curl -o x, wget -O x.
    const outputs = [];
    if (seg.head === 'dd') seg.args.forEach((a) => { if (a.startsWith('of=')) outputs.push(a.slice(3)); });
    if (seg.head === 'curl' || seg.head === 'wget') {
      const out = readTransfer(seg.head, seg.args).output;
      if (out) outputs.push(out);
    }
    if (outputs.map(resolve).some((t) => t && isGuarded(t, false))) return true;
    if (INTERPRETER_HEAD_RE.test(seg.head)) interpreter = true;
  }
  // An interpreter can write any file it names, so with one in the command, naming a guarded path is a write.
  return interpreter && (mentions || guarded.some((g) => cmd.includes(g)));
}

// Agent hook files whose added hook commands are checked for network inline code (REQ-06, cause A).
const AGENT_HOOK_FILE_RE = /(^|\/)(\.claude[^/]*\/settings[^/]*\.json|\.gemini\/settings\.json|\.codex\/hooks\.json|\.cursor\/hooks\.json)$/;

/**
 * Returns { deny, rule, reason, alternative, technique, mode, hits }. Every rule that matches is a hit
 * ({ rule, technique, mode }); the first hit in block mode decides the deny. The checks run in the same order as
 * before modes existed, so with every rule on block the deciding rule is the same as before.
 */
/**
 * A shell write into an agent's hook settings (`cat > .claude/settings.local.json <<EOF`, `echo ... | tee`, `cp x`)
 * that adds a hook with network code, or whose text can't be seen (a copy, another program's output).
 */
function shellHookWrite(cmds, cwd, home) {
  const abs = (w) => { const n = normalize(w, home); return n.startsWith('/') ? path.resolve(n) : path.resolve(cwd || '/', n); };
  const isHookFile = (w) => typeof w === 'string' && AGENT_HOOK_FILE_RE.test(abs(w));
  const textOf = (c) => {
    const k = programIndex(c.words);
    const head = path.basename(c.words[k] || '');
    const args = c.words.slice(k + 1).filter((a) => !a.startsWith('-'));
    if (/^(echo|printf)$/.test(head)) return args.join(' ').replace(/\\n/g, '\n');
    if (head === 'cat' && !args.length || head === 'tee') {
      if (c.stdin !== null) return c.stdin;
      if (c.herestring !== null) return c.herestring;
      if (c.pipedFrom) return textOf(c.pipedFrom);
    }
    return null;
  };
  const hasNet = (text) => {
    const found = hookCommandsIn(text) ?? [...text.matchAll(/"command"\s*:\s*("(?:[^"\\]|\\.)*")/g)].map((m) => { try { return JSON.parse(m[1]); } catch { return ''; } });
    return found.some((c) => netInParsed(shellParse(c)));
  };
  for (const c of cmds) {
    const k = programIndex(c.words);
    const head = path.basename(c.words[k] || '');
    const args = c.words.slice(k + 1).filter((a) => !a.startsWith('-'));
    const targets = c.redirects.filter((r) => /^(>|>>|>\||&>|&>>|<>)$/.test(r.op)).map((r) => r.target);
    if (head === 'tee') targets.push(...args);
    if (/^(cp|mv|ln|install|ditto|rsync)$/.test(head) && args.length) {
      if (isHookFile(args[args.length - 1])) return true; // the copied text isn't visible: use the Edit tool
    }
    if (!targets.some(isHookFile)) continue;
    const text = textOf(c);
    if (text === null || hasNet(text)) return true;
  }
  return false;
}

function evaluate(payload, ctx, settings = loadSettings(ctx)) {
  const home = ctx.home;
  const toolName = payload.tool_name || payload.toolName || '';
  const input = payload.tool_input || payload.toolInput || {};
  // `mac-yolo-credential-guard check -- <cmd>` only evaluates <cmd>; it doesn't run it. Its payload is dropped up
  // to the end of that command part, so `check -- x; security dump-keychain` is still caught.
  const rawCmd = commandOf(payload);
  const cmd = normalize(rawCmd, home)
    .replace(new RegExp(`((?:^|[\\s/])${MARKER}(?:\\.js)?\\s+check)\\b[^;&|\\n]*`, 'g'), '$1');
  const cwd = payload.cwd ? normalize(payload.cwd, home) : '';
  const filePaths = pathFields(input).concat(payload.file_path ? [payload.file_path] : []).map((p) => normalize(p, home));
  const segs = cmd ? segments(cmd) : [];
  // Inline code (`python3 -c "import os; os.system('security ...')"`) is split by the ; inside it, so when any
  // interpreter runs, the whole command is scanned as code too.
  if (segs.some((s) => INTERPRETER_HEAD_RE.test(s.head))) segs.push({ head: 'sh', text: cmd, args: [], whole: true });

  const hits = [];
  const add = (rule) => { if (rule && !hits.some((h) => h.rule === rule)) hits.push({ rule, technique: RULES[rule].technique, mode: settings.modes[rule] }); };

  // A part that is only the word `security` does not count when the word is nothing but a search program's pattern.
  const bareCounts = segs.some(bareSecurity) ? !securityIsOnlySearchText(rawCmd) : true;
  if (segs.some((s) => keychainRead(s, bareCounts))) add('keychain');
  if (cmd && COOKIE_LIB_RE.test(cmd)) add('cookie-library');
  if (segs.some(quarantineStrip)) add('quarantine');
  if (segs.some(launchctlSecret)) add('launchctl-secret');

  const storeRule = () => {
    if (cmd) {
      const nearBrowser = referencesBrowserRoot(cmd) || BROWSER_VENDOR_RE.test(cmd) || (cwd && (referencesBrowserRoot(cwd) || BROWSER_VENDOR_RE.test(`${cwd}/`)));
      if (nearBrowser && (CHROMIUM_STORE_RE.test(cmd) || COPY_TOOL_RE.test(cmd) || /\bfind\b.*-exec/.test(cmd))) return 'browser-store';
      if (safariCookies(cmd, home) || /Cookies\.binarycookies/.test(cmd) || FIREFOX_RE.test(cmd)) return 'browser-store';
      const inKeychains = cwd && /\/Library\/Keychains(\/|$)/.test(cwd);
      if (KEYCHAIN_PATH_RE.test(cmd) || (inKeychains && /\.keychain(-db)?\b/.test(cmd)) || /(?:^|\s)Keychains\/\S*\.keychain/.test(cmd)) return 'keychain-file';
    }
    for (const p of filePaths) {
      if (referencesBrowserRoot(p) && CHROMIUM_STORE_RE.test(p)) return 'browser-store';
      if (safariCookies(p, home) || FIREFOX_RE.test(p)) return 'browser-store';
      if (KEYCHAIN_PATH_RE.test(p)) return 'keychain-file';
    }
    return null;
  };
  add(storeRule());

  if (guardConfigWrite(ctx, toolName, input, filePaths, segs.filter((x) => !x.whole), cmd, cwd, rawCmd)) add('guard-config');

  const work = readWorkFolders(ctx);
  if (work.length && ctx.env.MAC_YOLO_WORK_AGENT !== '1') {
    const touched = [...(cwd ? [cwd] : []), ...filePaths.map((p) => (cwd && !p.startsWith('/') ? path.resolve(cwd, p) : p))];
    for (const s of segs) {
      for (const w of [s.head, ...s.args]) {
        if (w.startsWith('/')) touched.push(w);
        else if (cwd && !w.startsWith('-') && !w.includes('=')) touched.push(path.resolve(cwd, w)); // cat work/a, git -C work
      }
    }
    if (touched.some((p) => p.startsWith('/') && work.some((w) => inside(p, w)))) add('work-folder');
  }

  // The newer rules read the raw command through shellParse (quotes and heredocs kept).
  const parsed = parsedCommands(payload);
  if (parsed.length) {
    if (netInParsed(parsed)) add('net-oneliner');
    if (uploadInParsed(parsed, settings.allowlist)) add('curl-upload');
    if (recorderInParsed(parsed, settings.recorders)) add('recorder');
    if (bannedInParsed(parsed, settings.bannedAgents)) add('banned-agent');
    if (shellHookWrite(parsed, cwd, home)) add('net-oneliner');
  }
  if (isWriteTool(toolName)) {
    for (const p of filePaths.map((x) => path.resolve(cwd && !x.startsWith('/') ? path.resolve(cwd, x) : x))) {
      if (!AGENT_HOOK_FILE_RE.test(p)) continue;
      if (addedHookCommands(toolName, input, p).some((c) => netInParsed(shellParse(c)))) add('net-oneliner');
    }
  }

  // The scan reads the raw text itself (quotes, substitutions, groups), apart from a `check -- <cmd>` payload.
  const scanText = String(rawCmd || '').replace(new RegExp(`((?:^|[\\s/])${MARKER}(?:\\.js)?\\s+check)\\b[^;&|\\n]*`, 'g'), '$1');
  const scanned = cmd ? scanCommand(scanText) : null;
  if (scanned && pipeToShellTree(scanned)) add('pipe-to-shell');
  // The session's own folder is never a reason to deny: only a `cd` inside this command sets the folder.
  if (tmpExecIn(normalize(maskQuoted(String(rawCmd || '')), home), null, home, 0)) add('tmp-exec');
  if (segs.some(tccTouch) || filePaths.some((p) => TCC_DB_RE.test(p))) add('tcc');
  if (segs.some((x) => !x.whole && falconTouch(x)) || (scanned && falconChain(scanText)) || filePaths.some((p) => FALCON_PATH_RE.test(p))) add('falcon');
  if (segs.some((s) => !s.whole && launchAgentChange(s))
    || (isWriteTool(toolName) && filePaths.some((p) => LAUNCH_DIR_RE.test(p)))) add('launch-agent');

  const decider = hits.find((h) => h.mode === 'block');
  if (decider) return { deny: true, ...RULES[decider.rule], rule: decider.rule, mode: 'block', hits };
  const ask = hits.find((h) => h.mode === 'ask');
  if (ask) return { deny: true, ...RULES[ask.rule], rule: ask.rule, mode: 'ask', hits, digest: callDigest(payload, ctx, filePaths, rawCmd, cwd) };
  const warn = hits.find((h) => h.mode === 'warn');
  if (warn) return { deny: false, ...RULES[warn.rule], rule: warn.rule, mode: 'warn', hits };
  return { deny: false, hits };
}

// ---------------------------------------------------------------- ask mode and policy digest

const APPROVAL_TTL_MS = 10 * 60 * 1000;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const approvalsDir = (ctx) => path.join(configDir(ctx), 'approvals');
const pendingDir = (ctx) => path.join(approvalsDir(ctx), 'pending');
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

/** JSON with object keys sorted, so equal values give equal text. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v === undefined ? null : v);
}

/** SHA-256 of the normalized call: tool name, arguments, target paths and working folder. A changed argument changes it. */
function callDigest(payload, ctx, filePaths, rawCmd, cwd) {
  const tool = payload.tool_name || payload.toolName || '';
  const args = payload.tool_input || payload.toolInput || {};
  const targets = filePaths.map((p) => (cwd && !p.startsWith('/') ? path.resolve(cwd, p) : p)).sort();
  return sha256(canonical({ tool, args, command: rawCmd || '', targets, cwd }));
}

/** Short SHA-256 of the effective rule modes and name lists, so a log line says which policy was in force. */
function policyDigest(settings) {
  const sorted = (l) => [...l].sort();
  return sha256(canonical({
    modes: settings.modes, uploadAllowlist: sorted(settings.allowlist), recorders: sorted(settings.recorders), bannedAgents: sorted(settings.bannedAgents),
    // Added only when set, so a file without overrides keeps the digest it had before overrides existed.
    ...(settings.agentModes && Object.keys(settings.agentModes).length ? { agentModes: settings.agentModes } : {}),
  })).slice(0, 12);
}

function readApprovalFile(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}

/**
 * Looks for ~/.config/mac-yolo/approvals/<digest>.json, unused and under 10 minutes old, and marks it used. Returns
 * { ok: true } or { ok: false, why }. A missing file is "no approval"; any other failure (the folder or file can't
 * be read, the file is not valid JSON) throws, and the caller denies.
 */
function consumeApproval(ctx, digest) {
  const file = path.join(approvalsDir(ctx), `${digest}.json`);
  const text = readApprovalFile(file);
  if (text === null) return { ok: false, why: 'none' };
  const a = JSON.parse(text);
  if (!a || a.digest !== digest) return { ok: false, why: 'mismatch' };
  if (a.used !== false) return { ok: false, why: 'used' };
  const age = ctx.now().getTime() - Date.parse(a.approvedAt);
  if (!(age >= 0 && age < APPROVAL_TTL_MS)) return { ok: false, why: 'expired' };
  // Claim it with a rename: of two hooks racing on one approval, only one rename succeeds.
  const claimed = path.join(approvalsDir(ctx), `${digest}.used.json`);
  try { fs.renameSync(file, claimed); } catch (e) { if (e.code === 'ENOENT') return { ok: false, why: 'used' }; throw e; }
  try { fs.writeFileSync(claimed, `${JSON.stringify({ ...a, used: true, usedAt: ctx.now().toISOString() })}\n`, { mode: 0o600 }); } catch { /* it is already claimed */ }
  return { ok: true };
}

/** Writes the pending request the menu bar lists: digest, rule, and a fixed summary with no command text, path or host. */
function writePending(ctx, verdict, agent, tool) {
  try {
    fs.mkdirSync(pendingDir(ctx), { recursive: true, mode: 0o700 });
    const entry = {
      digest: verdict.digest, rule: verdict.rule, agent, tool,
      summary: `${agent} ${tool || 'tool call'}: ${verdict.reason} (rule ${verdict.rule}, request ${verdict.digest.slice(0, 8)})`,
      requestedAt: ctx.now().toISOString(),
    };
    const file = path.join(pendingDir(ctx), `${verdict.digest}.json`);
    fs.writeFileSync(`${file}.tmp`, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    fs.renameSync(`${file}.tmp`, file);
  } catch { /* the call is already denied; the agent's message still names the rule */ }
}

/** Pending requests under 10 minutes old, newest first. Never throws. */
function listPending(ctx) {
  const out = [];
  let names = [];
  try { names = fs.readdirSync(pendingDir(ctx)); } catch { return out; }
  for (const n of names) {
    if (!/^[0-9a-f]{64}\.json$/.test(n)) continue;
    try {
      const e = JSON.parse(fs.readFileSync(path.join(pendingDir(ctx), n), 'utf8'));
      const age = ctx.now().getTime() - Date.parse(e.requestedAt);
      if (e.digest === n.slice(0, 64) && age >= 0 && age < APPROVAL_TTL_MS) out.push(e);
    } catch { /* skip */ }
  }
  return out.sort((a, b) => Date.parse(b.requestedAt) - Date.parse(a.requestedAt));
}

function pendingEntry(ctx, digest) {
  if (!DIGEST_RE.test(digest || '')) throw new Error('give the 64-character request digest');
  const e = listPending(ctx).find((x) => x.digest === digest);
  if (!e) throw new Error('no pending request for that digest (it may have expired)');
  return e;
}

/** Approve writes the approval file for that exact digest, and only for a digest that has a pending request. */
function approve(ctx, digest) {
  const e = pendingEntry(ctx, digest);
  fs.mkdirSync(approvalsDir(ctx), { recursive: true, mode: 0o700 });
  const file = path.join(approvalsDir(ctx), `${digest}.json`);
  fs.writeFileSync(`${file}.tmp`, `${JSON.stringify({ digest, rule: e.rule, approvedAt: ctx.now().toISOString(), used: false })}\n`, { mode: 0o600 });
  fs.renameSync(`${file}.tmp`, file);
  fs.unlinkSync(path.join(pendingDir(ctx), `${digest}.json`));
  return { approved: true, digest, rule: e.rule, validMinutes: APPROVAL_TTL_MS / 60000 };
}

function denyPending(ctx, digest) {
  pendingEntry(ctx, digest);
  fs.unlinkSync(path.join(pendingDir(ctx), `${digest}.json`));
  return { denied: true, digest };
}

const LOG_FILE = 'credential-guard.jsonl';
const HEARTBEAT_FILE = 'credential-guard.heartbeat';
const LOG_MAX_BYTES = 5 * 1024 * 1024;

function logDeny(ctx, entry) {
  logLines(ctx, [entry]);
}

/** Creates the log folder as 700 when it does not exist yet. */
function ensureLogDir(ctx) {
  if (fs.mkdirSync(ctx.logDir, { recursive: true, mode: 0o700 })) fs.chmodSync(ctx.logDir, 0o700);
}

/** Appends JSON lines to the guard log; rotates it to .1 once it passes 5 MB. Never throws. */
function logLines(ctx, entries) {
  if (!entries.length) return;
  try {
    ensureLogDir(ctx);
    const file = path.join(ctx.logDir, LOG_FILE);
    const max = ctx.logMaxBytes || LOG_MAX_BYTES;
    try {
      // Rename only while still over the limit; two hooks rotating at once can lose one batch (accepted).
      if (fs.statSync(file).size > max) fs.renameSync(file, `${file}.1`);
    } catch { /* no log yet */ }
    fs.appendFileSync(file, entries.map((e) => `${JSON.stringify(e)}\n`).join(''), { mode: 0o600 });
    // A log made wider by an older version or by hand holds command text now: tighten it on every append.
    if ((fs.statSync(file).mode & 0o077) !== 0) fs.chmodSync(file, 0o600);
  } catch {
    // logging must never break the hook
  }
}

/** Base names of the agent's parent process chain, at most 6 levels and 1.5 s in total. */
function parentChain(ctx) {
  const out = [];
  let pid = Number(ctx.ppid);
  if (!ctx.run || !Number.isInteger(pid) || pid <= 1) return out;
  const start = Date.now();
  for (let i = 0; i < 6 && pid > 1; i += 1) {
    const left = 1500 - (Date.now() - start);
    if (left <= 0) break;
    let r;
    try { r = ctx.run('/bin/ps', ['-o', 'ppid=,comm=', '-p', String(pid)], { timeout: Math.min(1000, left) }); } catch { break; }
    if (!r || r.status !== 0) break;
    const m = String(r.stdout || '').trim().match(/^(\d+)\s+(.+)$/);
    if (!m) break;
    out.push(path.basename(m[2].trim().replace(/^-/, '')).slice(0, 40)); // -zsh is a login zsh
    pid = Number(m[1]);
  }
  return out;
}

// One plain sentence per rule for the menu bar ("Why" in the blocked list). Every rule in RULES needs one.
const WHY = {
  keychain: 'tried to read saved passwords from the macOS Keychain',
  'keychain-file': 'tried to open a Keychain file, where the Mac keeps saved passwords',
  'browser-store': 'tried to read or copy browser cookies or saved passwords',
  'cookie-library': 'tried to load a library that decrypts browser cookies',
  quarantine: 'tried to remove the macOS safety flag on downloaded files (xattr)',
  'launchctl-secret': 'tried to put a secret where every program on this Mac can read it',
  'guard-config': 'tried to change Mac YOLO\'s own guard settings',
  'work-folder': 'tried to work in a work-only folder from an agent that is not a work agent',
  'net-oneliner': 'tried to run inline code that opens a network connection',
  'curl-upload': 'tried to upload a file to a site that is not on the allowlist',
  recorder: 'tried to start a screen or audio recorder',
  'banned-agent': 'tried to run an agent that the owner of this Mac has banned',
  'pipe-to-shell': 'tried to pipe a download straight into a shell',
  'tmp-exec': 'tried to run a program from a temporary folder',
  tcc: 'tried to change or read macOS privacy permissions',
  'launch-agent': 'tried to add or change a program that starts at every login',
  falcon: 'tried to touch the CrowdStrike Falcon security sensor',
  pause: 'tried to run while all agent actions are paused',
  'internal-error': 'made the guard fail, so it was blocked to be safe',
  parse_error: 'sent a call the guard could not read',
};

// The log never holds anything the person or an agent typed where a program name goes. A program is logged by name
// only when it is in this one fixed list of well-known programs; anything else is the literal OTHER_PROGRAM. The same
// goes for the subcommand word: only the listed words of a listed program (git push, aws configure), never a value.
const OTHER_PROGRAM = 'other program';
const LOGGED_PROGRAMS = [
  'bash', 'zsh', 'sh', 'fish', 'dash', 'git', 'gh', 'aws', 'gcloud', 'az', 'npm', 'npx', 'pnpm', 'yarn', 'node', 'python', 'python3', 'pip', 'pip3',
  'brew', 'curl', 'wget', 'ssh', 'scp', 'rsync', 'sftp', 'nc', 'docker', 'kubectl', 'helm', 'terraform', 'security', 'osascript', 'open', 'cat', 'ls',
  'cp', 'mv', 'rm', 'mkdir', 'touch', 'chmod', 'chown', 'ln', 'sed', 'awk', 'grep', 'rg', 'find', 'head', 'tail', 'sort', 'cut', 'tr', 'tee', 'echo',
  'printf', 'cd', 'pwd', 'export', 'source', 'eval', 'exec', 'tar', 'zip', 'unzip', 'gzip', 'openssl', 'gpg', 'op', 'vault', 'make', 'cargo', 'go',
  'ruby', 'bundle', 'gem', 'java', 'mvn', 'gradle', 'dotnet', 'swift', 'swiftc', 'xcodebuild', 'sudo', 'env', 'xargs', 'xattr', 'launchctl', 'defaults',
  'tccutil', 'systemextensionsctl', 'plutil', 'ps', 'kill', 'pkill', 'lsof', 'sqlite3', 'mysql', 'psql', 'redis-cli', 'jq', 'diff', 'date', 'base64',
  'pbcopy', 'pbpaste', 'screencapture', 'say', 'codesign', 'spctl', 'hdiutil', 'dscl', 'sqlcmd', 'mongosh', 'sshpass', 'nohup', 'time', 'test', 'true',
];
const SUBCOMMANDS = {
  git: ['add', 'branch', 'checkout', 'clone', 'commit', 'config', 'diff', 'fetch', 'init', 'log', 'merge', 'pull', 'push', 'rebase', 'remote', 'reset', 'restore', 'stash', 'status', 'switch', 'tag', 'worktree'],
  gh: ['api', 'auth', 'issue', 'pr', 'release', 'repo', 'run', 'secret', 'workflow'],
  aws: ['configure', 'ec2', 'iam', 'lambda', 's3', 'secretsmanager', 'sso', 'sts'],
  gcloud: ['auth', 'compute', 'config', 'projects'],
  az: ['account', 'login'],
  npm: ['ci', 'config', 'exec', 'install', 'login', 'publish', 'run', 'test', 'token'],
  docker: ['build', 'compose', 'exec', 'login', 'ps', 'pull', 'push', 'run'],
  kubectl: ['apply', 'config', 'delete', 'exec', 'get', 'logs'],
  vault: ['kv', 'login', 'read', 'write'],
  op: ['item', 'read', 'run', 'signin'],
  security: ['add-generic-password', 'delete-generic-password', 'dump-keychain', 'export', 'find-generic-password', 'find-internet-password', 'import', 'list-keychains', 'unlock-keychain'],
  launchctl: ['bootout', 'bootstrap', 'getenv', 'kickstart', 'list', 'load', 'print', 'setenv', 'unload'],
  defaults: ['delete', 'read', 'write'],
  systemextensionsctl: ['list', 'uninstall'],
  tccutil: ['reset'],
};
const PROGRAM_SET = new Set(LOGGED_PROGRAMS);
const programWord = (token) => {
  const name = typeof token === 'string' ? token.slice(token.lastIndexOf('/') + 1) : '';
  return PROGRAM_SET.has(name) ? name : null;
};
const subcommandOf = (prog, word) => (Object.prototype.hasOwnProperty.call(SUBCOMMANDS, prog) && SUBCOMMANDS[prog].includes(word) ? word : null);
function commandShape(text) {
  const head = String(text == null ? '' : text).slice(0, 2000).split(/[|;&<>\n`]|\$\(/, 1)[0];
  const tokens = head.match(/\S+/g) || [];
  let i = 0;
  while (i < tokens.length && i < 40 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1;
  while (i < tokens.length && i < 40 && ['sudo', 'env', 'command'].includes(tokens[i])) i += 1;
  if (!tokens[i]) return '';
  const prog = programWord(tokens[i]);
  if (!prog) return OTHER_PROGRAM;
  const sub = subcommandOf(prog, tokens[i + 1]);
  return sub ? `${prog} ${sub}` : prog;
}
const SUMMARY_MAX = 80;
// Tool names, file extensions, long flags and config file names are logged only from these fixed lists; anything else is a fixed word.
const LOGGED_TOOLS = new Set(['Bash', 'Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'Task', 'TodoWrite',
  'beforeShellExecution', 'beforeReadFile', 'beforeMCPExecution', 'beforeSubmitPrompt', 'afterFileEdit', 'shell', 'apply_patch', 'local_shell',
  'exec_command', 'run_shell_command', 'read_file', 'write_file', 'edit_file', 'replace', 'list_directory']);
const loggedTool = (name) => (typeof name !== 'string' || !name ? '' : LOGGED_TOOLS.has(name) ? name : /^mcp__/.test(name) ? 'mcp tool' : 'other tool');
const LOGGED_EXTENSIONS = new Set(['.env', '.pem', '.key', '.p12', '.pfx', '.keychain', '.keychain-db', '.json', '.yml', '.yaml', '.toml', '.txt', '.md', '.sh', '.py',
  '.js', '.ts', '.plist', '.db', '.sqlite', '.log', '.cfg', '.conf', '.ini', '.pub', '.crt', '.cer', '.csv', '.html', '.css', '.swift', '.go', '.rb', '.rs']);
const LOGGED_LONG_FLAGS = new Set(['--force', '--hard', '--recursive', '--verbose', '--version', '--help', '--all', '--user', '--header', '--data', '--output', '--silent',
  '--insecure', '--password-stdin', '--with-token', '--no-verify', '--global', '--system', '--name', '--region', '--profile', '--quiet', '--yes', '--dry-run', '--rebuild', '--prod', '--production', '--save-dev']);
// A parent process is logged only when it is a listed program or one of these well-known hosts; anything else is OTHER_PROGRAM.
const LOGGED_HOSTS = new Set(['claude', 'codex', 'cursor', 'gemini', 'herdr', 'Terminal', 'iTerm2', 'ghostty', 'Warp', 'tmux', 'screen', 'login', 'launchd', 'Electron',
  'Code', 'zed', 'kitty', 'alacritty', 'wezterm-gui', 'grok', 'hermes', 'openclaw']);
const loggedParent = (name) => { const n = String(name).slice(String(name).lastIndexOf('/') + 1); return PROGRAM_SET.has(n) || LOGGED_HOSTS.has(n) ? n : OTHER_PROGRAM; };
const LOGGED_CONFIG_FILES = new Set(['settings.json', 'settings.local.json', 'config.toml', 'hooks.json', 'mcp.json', 'config.json', 'credential-guard.json',
  'credentials', 'config', 'authorized_keys', 'known_hosts', 'id_rsa', 'id_ed25519', 'login.keychain-db', '.claude.json']);
// Flag names only: long flags by name, short flags of one or two letters, and a short list of common longer clusters
// (-rf, -la, -xzf). A glued value such as -phunter2 or -ppass is never a flag name, so it stays out.
const SHORT_CLUSTERS = new Set(['-rf', '-fr', '-rfv', '-la', '-lah', '-alh', '-ltr', '-xzf', '-xvf', '-czf', '-cvf', '-fsL', '-sSL', '-fsSL', '-fSL']);
const FLAG_RE = { test: (t) => LOGGED_LONG_FLAGS.has(t) || /^-[A-Za-z]{1,2}$/.test(t) || SHORT_CLUSTERS.has(t) };
// Dot-folders whose paths name a setting, not the person's work, so a blocked edit there may show its path.
// A path in a summary is only a fixed prefix from this list, a literal ellipsis for everything in between, and a file name from
// LOGGED_CONFIG_FILES: never a directory or name the caller supplied.
const CONFIG_PREFIXES = ['.claude', '.cursor', '.codex', '.gemini', '.config', '.local/share/mac-yolo-safeguards', '.yolo', '.ssh', '.aws',
  'Library/LaunchAgents', 'Library/Keychains', 'Library/Application Support/Google/Chrome'];
const CONFIG_PATH_RE = new RegExp(`^~/(${CONFIG_PREFIXES.map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})/`);
/** "~/.claude/settings.json" or "~/.claude/…/settings.json", or null when the path is not a listed prefix plus a listed file name. */
function configPathShape(rel, base) {
  const m = typeof rel === 'string' ? rel.match(CONFIG_PATH_RE) : null;
  if (!m || !LOGGED_CONFIG_FILES.has(base)) return null;
  return rel === `${m[0]}${base}` ? rel : `${m[0]}\u2026/${base}`;
}
function configPathIsFixed(text) {
  return CONFIG_PREFIXES.some((x) => LOGGED_CONFIG_FILES.size > 0 && [...LOGGED_CONFIG_FILES].some((f) => text === `~/${x}/${f}` || text === `~/${x}/\u2026/${f}`));
}

/**
 * Plain shape of what the agent tried, for the blocked-actions list: the program and flag names of the first command
 * ("rm -rf …"), a subcommand word only after git, gh, security, launchctl, npm, node or python3, or the tool and a
 * settings path ("Edit ~/.claude/settings.json"). Argument values never appear: `echo hunter2` logs "echo …" and
 * `cat id_rsa` logs "cat …", so a token, URL or project file name in the call stays out of the log.
 */
function actionSummary(payload, home) {
  const input = payload.tool_input || payload.toolInput || {};
  const tool = payload.tool_name || payload.hook_event_name || '';
  let cmd = typeof input.command === 'string' ? input.command : typeof payload.command === 'string' ? payload.command : null;
  if (Array.isArray(input.command)) {
    const argv = input.command.map(String);
    cmd = argv.length >= 3 && /^-[a-z]*c$/.test(argv[1]) ? argv.slice(2).join(' ') : argv.join(' ');
  }
  if (cmd !== null) {
    const segments = cmd.split(/\|\||&&|[|;&\n]/).map((s) => s.trim()).filter(Boolean);
    const tokens = (segments[0] || '').split(/\s+/).filter((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t));
    while (tokens[0] === 'sudo' || tokens[0] === 'env' || tokens[0] === 'command') tokens.shift();
    if (!tokens.length) return null;
    const prog = programWord(tokens[0]);
    if (!prog) return `${OTHER_PROGRAM}${segments.length > 1 ? ` (+${segments.length - 1} more)` : ''}`;
    const out = [prog];
    let dropped = false;
    for (const t of tokens.slice(1)) {
      if (out.length >= 5) { dropped = true; break; }
      if (FLAG_RE.test(t) || (out.length === 1 && subcommandOf(prog, t))) out.push(t);
      else dropped = true;
    }
    let s = out.join(' ') + (dropped ? ' …' : '');
    if (segments.length > 1) s += ` (+${segments.length - 1} more)`;
    return s.slice(0, SUMMARY_MAX);
  }
  const file = input.file_path || input.path || input.notebook_path || payload.file_path;
  if (typeof file === 'string' && file) {
    const rel = home && file.startsWith(`${home}/`) ? `~${file.slice(home.length)}` : file;
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file);
    const shown = configPathShape(rel, base) || (LOGGED_EXTENSIONS.has(ext) ? `a ${ext} file` : 'a file');
    return `${loggedTool(tool) || 'read'} ${shown}`.slice(0, SUMMARY_MAX);
  }
  return tool ? loggedTool(tool) : null;
}

/** True only for a summary that has exactly the fixed shapes actionSummary writes now. Older rows are checked on read, never trusted. */
function summaryIsFixed(text) {
  if (typeof text !== 'string' || !text || text.length > SUMMARY_MAX) return false;
  const rest = text.replace(/ \(\+\d+ more\)$/, '').replace(/ …$/, '');
  if (rest === OTHER_PROGRAM) return true;
  const toks = rest.split(' ');
  if (PROGRAM_SET.has(toks[0])) {
    const i = toks[1] && subcommandOf(toks[0], toks[1]) ? 2 : 1;
    return toks.length <= 5 && toks.slice(i).every((t) => FLAG_RE.test(t));
  }
  const m = rest.match(/^(\S+) (.+)$/);
  if (m && (LOGGED_TOOLS.has(m[1]) || m[1] === 'read' || m[1] === 'mcp' || m[1] === 'other')) {
    const what = m[2];
    if (what === 'a file' || what === 'tool') return true;
    const e = what.match(/^a (\.[a-z0-9-]+) file$/);
    if (e) return LOGGED_EXTENSIONS.has(e[1]);
    return configPathIsFixed(what);
  }
  return LOGGED_TOOLS.has(rest) || rest === 'mcp tool' || rest === 'other tool';
}

/** The shell command of a tool call, or null for a file tool. Same extraction as actionSummary. */
function commandText(payload) {
  const input = payload.tool_input || payload.toolInput || {};
  let cmd = typeof input.command === 'string' ? input.command : typeof payload.command === 'string' ? payload.command : null;
  if (Array.isArray(input.command)) {
    const argv = input.command.map(String);
    cmd = argv.length >= 3 && /^-[a-z]*c$/.test(argv[1]) ? argv.slice(2).join(' ') : argv.join(' ');
  }
  return cmd;
}

/** The argument-free fields of a log row. Each part is isolated: a failure here never changes the verdict or drops the row. */
function logFields(payload, ctx) {
  const out = {};
  try { const summary = actionSummary(payload, ctx.home); if (summary) out.summary = summary; } catch { /* log without it */ }
  try { const cmd = commandText(payload); const command = cmd ? commandShape(cmd) : ''; if (command) out.command = command; } catch { /* log without it */ }
  return out;
}

// ---------------------------------------------------------------- what a guard-config block was aimed at (log only)

// Everything in this part runs after the verdict and only fills log fields, so it cannot change what the guard allows.
// Each value is from a fixed list, or a folder, session or pane name reduced by loggedName.
const GUARD_DIR_SHAPE = '~/.config/mac-yolo';
const GUARD_PROGRAM_SHAPE = `~/.local/share/mac-yolo-safeguards/${MARKER}.js`;
const GUARD_DIR_FILES = ['PAUSE', SETTINGS_FILE, 'work-folders', 'approvals'];
const HOOK_FILE_WORDS = 'an agent hook settings file';
const HOME_WORDS = 'the home folder';
const WORK_WORDS = 'a work folder';
const GUARD_CLI_WORDS = [...GUARD_WRITE_SUBS, 'work-folders'];
const GUARD_HOWS = ['edit', 'script', 'command', 'guard-cli'];
const LIST_KEYS = ['uploadAllowlist', 'recorders', 'bannedAgents'];
const HOOK_SWITCH_KEYS = ['disableAllHooks', 'allowManagedHooksOnly'];
const CHANGE_KEYS = new Set([...Object.keys(RULES).map((id) => `rules.${id}`), ...LIST_KEYS, ...HOOK_SWITCH_KEYS, 'hooks']);
const CHANGE_WORDS = new Set(['true', 'false', 'not set', 'another value', 'different entries', 'guard hook installed', 'guard hook removed', ...MODES]);
const changeWordIsFixed = (v) => typeof v === 'string' && (CHANGE_WORDS.has(v) || /^\d{1,4} entries$/.test(v));
const SETTING_READ_MAX_BYTES = 1024 * 1024;
const TOKEN_PREFIX_RE = /^(sk-|ghp_|gho_|ghs_|github_pat_|glpat-|xox[abpr]-|AKIA|ASIA|AIza|eyJ)/;

/** True only for a target in one of the fixed shapes guardTarget writes. */
function targetIsFixed(t) {
  if (typeof t !== 'string' || !t) return false;
  return t === GUARD_DIR_SHAPE || t === GUARD_PROGRAM_SHAPE || t === HOOK_FILE_WORDS
    || GUARD_DIR_FILES.some((f) => t === `${GUARD_DIR_SHAPE}/${f}`)
    || GUARD_CLI_WORDS.some((w) => t === `guard command: ${w}`)
    || configPathIsFixed(t);
}

/** A folder, herdr session or pane name for the log: plain characters, 40 at most, and '' when it has the shape of a token. */
function loggedName(v) {
  if (typeof v !== 'string' || TOKEN_PREFIX_RE.test(v)) return '';
  const s = v.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 40);
  const longMixedRun = (s.match(/[A-Za-z0-9]{16,}/g) || []).some((run) => /\d/.test(run) && /[A-Za-z]/.test(run));
  // Separators do not hide a token: a UUID or a dashed key is judged with them removed. Four or more switches between
  // letters and digits in 12 or more characters, or 12 digits in a row, is a key or an id, not a folder name.
  const joined = s.replace(/[^A-Za-z0-9]/g, '');
  const switches = (joined.match(/[A-Za-z](?=\d)|\d(?=[A-Za-z])/g) || []).length;
  const scrambled = (joined.length >= 12 && switches >= 4) || /\d{12,}/.test(joined);
  return longMixedRun || scrambled ? '' : s;
}

/** The paths the guard-config rule protects: the guard's folder, its installed program and the agents' hook files. */
function guardedPaths(ctx) {
  const extraClaude = claudeDirs(ctx, { scanLaunchers: false }).flatMap((d) => [path.join(d, 'settings.json'), path.join(d, 'settings.local.json')]);
  return [configDir(ctx), path.join(installDir(ctx), `${MARKER}.js`), ...new Set([...Object.values(hookFiles(ctx)), ...extraClaude])];
}

/** The fixed words for a path that is a guarded path, inside one, or a folder holding one; null for any other path. */
function guardedShape(abs, guarded, ctx) {
  const hit = guarded.find((g) => inside(abs, g)) || guarded.find((g) => inside(g, abs));
  if (!hit) return null;
  const p = inside(abs, hit) ? abs : hit;
  const cfg = configDir(ctx);
  if (inside(p, cfg)) {
    const first = path.relative(cfg, p).split(path.sep)[0];
    return GUARD_DIR_FILES.includes(first) ? `${GUARD_DIR_SHAPE}/${first}` : GUARD_DIR_SHAPE;
  }
  if (p === path.join(installDir(ctx), `${MARKER}.js`)) return GUARD_PROGRAM_SHAPE;
  const rel = p.startsWith(`${ctx.home}/`) ? `~${p.slice(ctx.home.length)}` : p;
  return configPathShape(rel, path.basename(p)) || HOOK_FILE_WORDS;
}

/** The setting a file tool would change, in fixed words, or null when the file's text before and after cannot be compared. */
function settingChange(toolName, input, file, ctx) {
  let current = '';
  try {
    // Never open anything but a small regular file here: a pipe named settings.json would hang the hook.
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > SETTING_READ_MAX_BYTES) return null;
    current = fs.readFileSync(file, 'utf8');
  } catch (e) { if (e.code !== 'ENOENT') return null; }
  const next = editedText(toolName, input, current);
  if (typeof next !== 'string' || next.length > SETTING_READ_MAX_BYTES) return null;
  const plain = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
  let a;
  let b;
  try { a = plain(current.trim() ? JSON.parse(current) : {}); b = plain(JSON.parse(next)); } catch { return null; }
  if (!a || !b) return null;
  const word = (v) => (v === undefined ? 'not set' : v === true ? 'true' : v === false ? 'false' : MODES.includes(v) ? v
    : Array.isArray(v) ? `${Math.min(v.length, 9999)} entries` : 'another value');
  const diff = (key, x, y) => {
    if (JSON.stringify(x) === JSON.stringify(y)) return null;
    const from = word(x);
    const to = word(y);
    return { key, from, to: from !== to ? to : Array.isArray(y) ? 'different entries' : 'another value' };
  };
  if (file === path.join(configDir(ctx), SETTINGS_FILE)) {
    const ra = plain(a.rules) || {};
    const rb = plain(b.rules) || {};
    for (const id of Object.keys(RULES)) { const d = diff(`rules.${id}`, ra[id], rb[id]); if (d) return d; }
    for (const k of LIST_KEYS) { const d = diff(k, a[k], b[k]); if (d) return d; }
    return null;
  }
  for (const k of HOOK_SWITCH_KEYS) { const d = diff(k, a[k], b[k]); if (d) return d; }
  if (current.includes(MARKER) && !next.includes(MARKER)) return { key: 'hooks', from: 'guard hook installed', to: 'guard hook removed' };
  return null;
}

/**
 * What a call the guard-config rule matched was aimed at: { target, how, via?, change? } in fixed words, or null when
 * no guarded path can be named. The same function reads a raw command an older guard left in the log.
 */
function guardTarget(payload, ctx, guarded = guardedPaths(ctx)) {
  const home = ctx.home;
  const input = payload.tool_input || payload.toolInput || {};
  const cwd = typeof payload.cwd === 'string' && payload.cwd ? normalize(payload.cwd, home) : '';
  const abs = (w) => (w.startsWith('/') ? path.resolve(w) : cwd ? path.resolve(cwd, w) : '');
  const rawCmd = commandOf(payload);
  if (!rawCmd) {
    const files = pathFields(input).concat(payload.file_path ? [payload.file_path] : []).map((p) => abs(normalize(p, home))).filter(Boolean);
    const file = files.find((p) => guarded.some((g) => inside(p, g)));
    if (!file) return null;
    const out = { target: guardedShape(file, guarded, ctx), how: 'edit' };
    const change = settingChange(payload.tool_name || payload.toolName || '', input, file, ctx);
    if (change) out.change = change;
    return out;
  }
  const segs = segments(normalize(rawCmd, home));
  for (const seg of segs) {
    const call = guardCall(seg);
    if (!call) continue;
    if (GUARD_WRITE_SUBS.has(call.sub)) return { target: `guard command: ${call.sub}`, how: 'guard-cli' };
    if (call.sub === 'work-folders' && call.action && call.action !== 'list') return { target: 'guard command: work-folders', how: 'guard-cli' };
  }
  // A part that does not start with a known program is a piece of the one before it: `node -e "require('/x')"` is split at the bracket.
  const named = (matches) => {
    let program = null;
    for (const seg of segs) {
      program = programWord(seg.head) || program;
      for (const w of seg.text.split(/[\s<>=,]+/)) {
        const p = w ? abs(w) : '';
        if (p && matches(p)) return { target: guardedShape(p, guarded, ctx), how: program && INTERPRETER_HEAD_RE.test(program) ? 'script' : 'command', via: program || OTHER_PROGRAM };
      }
    }
    return null;
  };
  const homeDir = path.resolve(home);
  return named((p) => guarded.some((g) => inside(p, g)))
    || named((p) => p !== homeDir && inside(p, homeDir) && guarded.some((g) => inside(g, p)))
    || (GUARD_DIR_WORD_RE.test(rawCmd) ? { target: GUARD_DIR_SHAPE, how: 'command' } : null);
}

/** Where the call ran: the project folder's name and herdr's session and pane, each reduced by loggedName. */
function whereFields(payload, ctx) {
  const out = {};
  const cwd = typeof payload.cwd === 'string' && payload.cwd.startsWith('/') ? path.resolve(payload.cwd) : '';
  if (cwd && cwd !== '/') {
    const project = cwd === path.resolve(ctx.home) ? HOME_WORDS : readWorkFolders(ctx).some((w) => inside(cwd, w)) ? WORK_WORDS : loggedName(path.basename(cwd));
    if (project) out.project = project;
  }
  const env = ctx.env || {};
  const session = loggedName(env.HERDR_SESSION);
  if (session) out.session = session;
  const pane = loggedName(env.HERDR_PANE_ID);
  if (pane) out.pane = pane;
  return out;
}

// ---------------------------------------------------------------- read or write (log only)
// The guard blocks every call that names a guarded file, because a script can write to any file it names. That says
// nothing about what the call did, so the log also records whether the call only read ('read'), changed something
// ('write'), or could not be told ('unknown'). Any sign of a write wins; a read needs every part to be a known reader.
const GUARD_ACCESS = ['read', 'write', 'unknown'];
const CLASSIFY_MAX_CHARS = 10000;
const READ_PROGRAMS = new Set(['cat', 'grep', 'egrep', 'fgrep', 'rg', 'head', 'tail', 'less', 'more', 'jq', 'ls', 'stat', 'wc', 'file', 'diff', 'cmp', 'sort', 'cut', 'tr', 'awk', 'sed', 'find', 'echo', 'printf', 'cd', 'pwd', 'test', '[', '[[', 'which', 'dirname', 'basename', 'realpath', 'nl', 'column', 'od', 'strings', 'shasum', 'md5', 'true', 'false', 'exit', 'wait']);
const WRITE_PROGRAMS = new Set(['tee', 'mv', 'rm', 'rmdir', 'cp', 'touch', 'chmod', 'chown', 'ln', 'truncate', 'dd', 'install', 'mkdir', 'patch', 'ed', 'ex', 'vi', 'vim', 'nano', 'unlink', 'shred', 'rsync', 'ditto', 'sponge', 'defaults', 'plutil', 'launchctl', 'xattr', 'chflags']);
const SHELL_WORDS = new Set(['for', 'while', 'until', 'do', 'done', 'if', 'then', 'else', 'elif', 'fi', 'case', 'esac', 'in']);
const WRAPPERS = new Set(['sudo', 'nice', 'time', 'env', 'command', 'builtin', 'nohup', 'exec']);
const SCRIPT_WRITE_RE = [
  /\.write\(|\.writelines\(|write_text\(|write_bytes\(|json\.dump\(|\.truncate\(/,
  /\bos\.(remove|unlink|rename|replace|rmdir|removedirs|makedirs|mkdir|chmod|chown|symlink|link|truncate|system|popen|exec\w*|spawn\w*)\(/,
  /\bshutil\.|\bsubprocess\b|\bPath\([^)]*\)\.(unlink|rename|replace|touch|mkdir|rmdir|chmod|symlink_to)\(/,
  /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|unlinkSync|renameSync|rmSync|copyFileSync|copyFile|mkdirSync|openSync|chmodSync|execSync|execFileSync|spawnSync|spawn)\s*\(/,
  /\bchild_process\b|\bfs\.promises\b|\bFile\.(write|delete|open)\b|\bIO\.write\b/,
  /\bsed\s+(-[A-Za-z]+\s+)*(-[A-Za-z]*i\b|--in-place)|\bperl\s+(-[A-Za-z]+\s+)*-[A-Za-z]*i\b|\bawk\s+-i\b/,
  /(^|[\s;|&"'(])(tee|mv|rm|cp|touch|chmod|chown|ln|truncate|dd|install)\s+[-~/.$"']/,
];
// Anything that can reach outside the files: a script that does one of these is not shown to be read-only.
const SCRIPT_UNKNOWN_RE = /\beval\s*\(|\bexec\s*\(|__import__|\bimportlib\b|\bctypes\b|\bsocket\b|\burllib\b|\brequests\b|\bfetch\s*\(|\bcompile\s*\(|\bgetattr\s*\(/;
const SCRIPT_READ_RE = /json\.load\(|\.read\(|\.readlines?\(|read_text\(|readFileSync|readFile\(|JSON\.parse|\brequire\s*\(|\btomllib\b|\bconfigparser\b|\bopen\(/;

/** The argument texts of the call whose "(" is at `start`, split at top-level commas; null when the brackets never close. */
function callArgs(s, start) {
  let depth = 0; let cur = ''; const args = []; let quote = '';
  for (let i = start; i < s.length; i += 1) {
    const ch = s[i];
    if (quote) { cur += ch; if (ch === quote && s[i - 1] !== '\\') quote = ''; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; if (depth > 1) cur += ch; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; if (depth === 0) { args.push(cur.trim()); return args; } cur += ch; continue; }
    if (ch === ',' && depth === 1) { args.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  return null;
}

/** 'write', 'read' or 'unknown' for every open( in a script: a literal mode with w, a, x or + writes; no mode or r reads. */
function openModes(script) {
  const out = [];
  const re = /(^|[^\w])(\.?)open\(/g;
  let m;
  while ((m = re.exec(script))) {
    const args = callArgs(script, m.index + m[0].length - 1);
    if (!args) { out.push('unknown'); continue; }
    const kw = args.find((a) => /^mode\s*=/.test(a));
    let mode = kw ? kw.replace(/^mode\s*=\s*/, '') : args[1];
    if (mode === undefined && m[2] === '.' && /^(['"])[rwabxt+]{1,4}\1$/.test(args[0] || '')) mode = args[0];
    if (mode === undefined) { out.push('read'); continue; }
    const lit = /^[rbRB]?(['"])([^'"]*)\1$/.exec(mode);
    out.push(!lit ? 'unknown' : /[wax+>]/.test(lit[2]) ? 'write' : 'read');
  }
  return out;
}

/** 'read', 'write' or 'unknown' for the shell command text of a call. Pure; never throws. */
function classifyAccess(rawCmd) {
  try {
    if (typeof rawCmd !== 'string' || !rawCmd.trim()) return 'unknown';
    // The patterns below can take seconds on a huge command; the guard runs on every call, so a long one is not sorted.
    if (rawCmd.length > CLASSIFY_MAX_CHARS) return 'unknown';
    const bodies = [];
    let shell = rawCmd.replace(/<<-?\s*(['"]?)(\w+)\1[^\n]*\n([\s\S]*?)(\n\s*\2\s*(?=\n|$)|$)/g, (all, q, tag, body) => { bodies.push(body); return `<<${tag}\n`; });
    const quoted = [];
    shell = shell.replace(/'([^']*)'|"((?:[^"\\]|\\.)*)"/g, (all, a, b) => { quoted.push(a === undefined ? b : a); return ' '; });
    const script = [...bodies, ...quoted].join('\n');
    const redirects = shell.replace(/\d*>&\d*-?|&>\s*\/dev\/null|\d*>>?\s*\/dev\/null|<<-?\s*\w+|<<<|<&\d/g, ' ');
    if (/>/.test(redirects)) return 'write';
    if (SCRIPT_WRITE_RE.some((re) => re.test(script) || re.test(shell))) return 'write';
    const modes = openModes(script);
    if (modes.includes('write')) return 'write';
    let sawReader = false;
    let unknown = modes.includes('unknown') || SCRIPT_UNKNOWN_RE.test(script);
    for (const seg of shell.split(/[|;&\n(){}]+/)) {
      const words = seg.trim().split(/\s+/).filter(Boolean);
      let i = 0;
      while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i]) || WRAPPERS.has(words[i]))) i += 1;
      if (i >= words.length || SHELL_WORDS.has(words[i])) continue;
      const head = path.basename(words[i]);
      if (WRITE_PROGRAMS.has(head)) return 'write';
      if (READ_PROGRAMS.has(head)) {
        if (head === 'find' && /\s-(delete|exec|execdir|ok|fprint\w*|fls)\b/.test(seg)) return 'write';
        // sort -o and --output name a file to write; an awk or sed program can write, pipe or run a command.
        if (head === 'sort' && /\s(-[A-Za-z]*o\b|--output)/.test(seg)) return 'write';
        if (head === 'awk' && /[>|]|system\s*\(|getline/.test(script)) return 'write';
        if (head === 'sed' && /(^|[;{\s'"])[we]\s+\S|\/[gip0-9]*[we]\s*($|['";}\s])/.test(script)) return 'write';
        sawReader = true;
      } else if (/^(python[0-9.]*|node|ruby|perl)$/.test(head)) {
        if (SCRIPT_READ_RE.test(script) || SCRIPT_READ_RE.test(seg)) sawReader = true;
        else unknown = true;
      } else unknown = true;
    }
    return unknown || !sawReader ? 'unknown' : 'read';
  } catch { return 'unknown'; }
}

/** What the call did to the guarded file: an edit tool writes; a shell command is read by its text. */
function guardAccess(payload) {
  try {
    const rawCmd = commandOf(payload);
    if (!rawCmd) return 'write';
    return classifyAccess(rawCmd);
  } catch { return 'unknown'; }
}

/** Only the guard-config fields that are in their fixed shapes. The hook writes through this, and the menu reads through it. */
function cleanGuardFields(e) {
  const out = {};
  if (!e || typeof e !== 'object') return out;
  if (targetIsFixed(e.target)) out.target = e.target;
  if (GUARD_HOWS.includes(e.how)) out.how = e.how;
  if (GUARD_ACCESS.includes(e.access)) out.access = e.access;
  if (typeof e.via === 'string' && (PROGRAM_SET.has(e.via) || e.via === OTHER_PROGRAM)) out.via = e.via;
  const c = e.change;
  if (c && typeof c === 'object' && CHANGE_KEYS.has(c.key) && changeWordIsFixed(c.from) && changeWordIsFixed(c.to)) out.change = { key: c.key, from: c.from, to: c.to };
  const name = (v) => typeof v === 'string' && v !== '' && loggedName(v) === v;
  if (e.project === HOME_WORDS || e.project === WORK_WORDS || name(e.project)) out.project = e.project;
  if (name(e.session)) out.session = e.session;
  if (name(e.pane)) out.pane = e.pane;
  return out;
}

function detectAgent(payload, flag) {
  if (AGENTS.includes(flag)) return flag;
  if (/^before/.test(payload.hook_event_name || '') || (typeof payload.command === 'string' && !payload.tool_input)) return 'cursor';
  return 'claude';
}

/** Runs the hook on raw stdin text. Returns { exitCode, stdout, stderr }. */
/** Touches credential-guard.heartbeat so the menu bar can tell the guard ran in the last 10 minutes. Never throws. */
function beat(ctx) {
  try {
    ensureLogDir(ctx);
    fs.writeFileSync(path.join(ctx.logDir, HEARTBEAT_FILE), `${ctx.now().toISOString()}\n`, { mode: 0o600 });
  } catch { /* the heartbeat must never break the hook */ }
}

/** The policy digest for a log line; 'unknown' when the settings can't be read, so logging never breaks the hook. */
function policyDigestOf(ctx, settings) {
  try { return policyDigest(settings || loadSettings(ctx)); } catch { return 'unknown'; }
}

function runHook(raw, agentFlag, ctx) {
  beat(ctx);
  let settings = null;
  try { settings = loadSettings(ctx); } catch { /* evaluate() will hit the same error and deny */ }
  // Kill switch: checked before the payload is even parsed, and runs no ps.
  const pauseFile = path.join(configDir(ctx), 'PAUSE');
  if (fs.existsSync(pauseFile)) {
    // The payload is read only to pick the reply shape; a payload that doesn't parse is still denied.
    let agent = AGENTS.includes(agentFlag) ? agentFlag : null;
    if (!agent) { try { agent = detectAgent(JSON.parse(raw) || {}, agentFlag); } catch { agent = 'claude'; } }
    logLines(ctx, [{ at: ctx.now().toISOString(), agent, rule: 'pause', mode: 'block', denied: true, ran: false, policyDigest: policyDigestOf(ctx, settings), parents: [] }]);
    const message = `mac-yolo credential guard: paused, every agent tool call is denied while ${pauseFile} exists. A person resumes agents by removing that file in their own terminal.`;
    if (agent === 'cursor') {
      return { exitCode: 2, stdout: `${JSON.stringify({ permission: 'deny', user_message: message, agent_message: message })}\n`, stderr: '' };
    }
    return { exitCode: 2, stdout: '', stderr: `${message}\n` };
  }
  let payload;
  try {
    payload = raw.trim() ? JSON.parse(raw) : {};
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) payload = {};
  } catch {
    logDeny(ctx, { at: ctx.now().toISOString(), agent: AGENTS.includes(agentFlag) ? agentFlag : 'unknown', rule: 'parse_error', denied: false, policyDigest: policyDigestOf(ctx, settings) });
    return { exitCode: 0, stdout: agentFlag === 'cursor' ? '{"permission":"allow"}\n' : '', stderr: '' };
  }
  const agent = detectAgent(payload, agentFlag);
  let verdict;
  try {
    verdict = evaluate(payload, ctx, settings ? settingsFor(settings, agent) : undefined);
  } catch {
    // A guard that crashes must not let the call through (exit 1 is a non-blocking error to the agents).
    verdict = { deny: true, rule: 'internal-error', technique: 'n/a', mode: 'block',
      reason: 'call made the credential guard fail, so it is denied to be safe',
      alternative: 'retry with a simpler tool call, or report it with `mac-yolo-credential-guard doctor`',
      hits: [{ rule: 'internal-error', technique: 'n/a', mode: 'block' }] };
  }
  const tool = loggedTool(payload.tool_name || payload.hook_event_name || '');
  let approvalId;
  if (verdict.deny && verdict.mode === 'ask') {
    // Fail closed: anything unexpected in the approval path keeps the call denied.
    try {
      const r = consumeApproval(ctx, verdict.digest);
      if (r.ok) { verdict = { ...verdict, deny: false }; approvalId = verdict.digest.slice(0, 16); }
      else writePending(ctx, verdict, agent, tool);
    } catch {
      verdict = { ...verdict, approvalError: true };
    }
  }
  if (verdict.hits.length) {
    // Only the shape of the action is logged (program and one subcommand word, never argument values), with one plain sentence for the rule.
    const at = ctx.now().toISOString();
    let parents = [];
    try { parents = parentChain(ctx).map(loggedParent); } catch { /* log without parents */ }
    const policy = policyDigestOf(ctx, settings);
    const fields = logFields(payload, ctx);
    // What a guard-config block was aimed at and where it ran. The verdict is already made; a failure here logs the row without them.
    let aimed = {};
    if (verdict.hits.some((h) => h.rule === 'guard-config')) {
      try { aimed = cleanGuardFields({ ...guardTarget(payload, ctx), ...whereFields(payload, ctx), access: guardAccess(payload) }); } catch { /* log without them */ }
    }
    const callId = verdict.mode === 'ask' && typeof verdict.digest === 'string' ? verdict.digest.slice(0, 16) : null;
    logLines(ctx, verdict.hits.map((h) => ({
      at, agent, tool, rule: h.rule, technique: h.technique, mode: h.mode, denied: verdict.deny && h.rule === verdict.rule, ran: !verdict.deny,
      policyDigest: policy, ...(approvalId && h.rule === verdict.rule ? { approvalId } : {}), ...(callId && h.rule === verdict.rule ? { callId } : {}),
      ...fields, ...(h.rule === 'guard-config' ? aimed : {}), ...(WHY[h.rule] ? { why: WHY[h.rule] } : {}), parents,
    })));
  }
  const tag = verdict.rule ? ` (rule ${verdict.rule}, ATT&CK ${verdict.technique})` : '';
  if (!verdict.deny && verdict.mode === 'warn') {
    const message = `mac-yolo credential guard: warning, this ${verdict.reason}. Allowed for now; consider: ${verdict.alternative}.${tag}`;
    if (agent === 'cursor') return { exitCode: 0, stdout: `${JSON.stringify({ permission: 'allow', user_message: message, agent_message: message })}\n`, stderr: '' };
    if (agent === 'codex') return { exitCode: 0, stdout: '', stderr: `${message}\n` };
    return { exitCode: 0, stdout: `${JSON.stringify({ systemMessage: message })}\n`, stderr: '' };
  }
  if (!verdict.deny) {
    return { exitCode: 0, stdout: agent === 'cursor' ? '{"permission":"allow"}\n' : '', stderr: '' };
  }
  let message = `mac-yolo credential guard: blocked because this ${verdict.reason}. Instead: ${verdict.alternative}.${tag}`;
  if (verdict.mode === 'ask') {
    message = verdict.approvalError
      ? `mac-yolo credential guard: denied because the approvals folder could not be read, so no approval could be checked.${tag}`
      : `mac-yolo credential guard: this ${verdict.reason} needs a person's approval. Ask them to approve request ${verdict.digest.slice(0, 8)} in the Mac YOLO menu bar (Pending approvals), then retry the exact same call; an approval works once, for 10 minutes.${tag}`;
  }
  if (agent === 'cursor') {
    return {
      exitCode: 2,
      stdout: `${JSON.stringify({ permission: 'deny', user_message: message, agent_message: message })}\n`,
      stderr: '',
    };
  }
  return { exitCode: 2, stdout: '', stderr: `${message}\n` };
}

// ---------------------------------------------------------------- install

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return fallback;
    throw new Error(`${file} is not valid JSON; leaving it alone`);
  }
}

function realTarget(file) {
  try { return fs.realpathSync(file); } catch { return file; } // a dotfiles symlink stays a symlink
}

const BACKUPS_KEPT = 5;
const REPLACED_KEPT = 3;

// Our hook's command, as hookCommand() writes it: the guard script's path, then `hook --agent <name>`. A config that
// only mentions the guard's name (a comment, a note) does not match.
const HOOK_COMMAND_RE = /mac-yolo-credential-guard\.js["']?\s+hook\s+--agent\s+(?:claude|codex|cursor)\b/;

function stringsIn(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => stringsIn(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => stringsIn(x, out));
  return out;
}

/** Does this config file hold our hook? JSON is parsed and its hook commands read; any other text needs a whole line with our command. */
function hasOurHook(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return false; }
  try { return stringsIn(JSON.parse(text).hooks).some((c) => HOOK_COMMAND_RE.test(c)); } catch { /* not JSON */ }
  return text.split('\n').some((line) => HOOK_COMMAND_RE.test(line));
}

/**
 * Prunes timestamped backups of `file` (the stamp sorts as text). Backups that hold our hook: the newest
 * BACKUPS_KEPT stay. Backups that do not (the person's config from before the guard, and the copies each
 * uninstall/install cycle adds): the newest BACKUPS_KEPT and the oldest one stay. `<file>.mac-yolo-original` has
 * another name and is never touched. Never throws.
 */
function pruneBackups(file) {
  try {
    const dir = path.dirname(file);
    const prefix = `${path.basename(file)}.mac-yolo-backup-`;
    const all = fs.readdirSync(dir).filter((n) => n.startsWith(prefix)).sort();
    const hooked = all.filter((n) => hasOurHook(path.join(dir, n)));
    const plain = all.filter((n) => !hooked.includes(n));
    const drop = [...hooked.slice(0, -BACKUPS_KEPT), ...plain.slice(1, -BACKUPS_KEPT)];
    for (const n of drop) fs.rmSync(path.join(dir, n), { force: true });
  } catch { /* a backup that cannot be pruned is left in place */ }
}

/** Keeps the newest `keep` files named `<base><infix>*` next to `file`. Never throws. */
function pruneByName(file, infix, keep) {
  try {
    const dir = path.dirname(file);
    const prefix = `${path.basename(file)}${infix}`;
    for (const n of fs.readdirSync(dir).filter((x) => x.startsWith(prefix)).sort().slice(0, -keep)) fs.rmSync(path.join(dir, n), { force: true });
  } catch { /* left in place */ }
}

function writeJsonAtomic(linkOrFile, data, ctx) {
  const file = realTarget(linkOrFile);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let mode = 0o600;
  if (fs.existsSync(file)) {
    mode = fs.statSync(file).mode & 0o777;
    const stamp = ctx.now().toISOString().replace(/[:.]/g, '-');
    fs.copyFileSync(file, `${file}.mac-yolo-backup-${stamp}`);
    // The person's config from before the guard is kept for good: copied once, and only from a file without our hook.
    if (!hasOurHook(file)) { try { fs.copyFileSync(file, `${file}.mac-yolo-original`, fs.constants.COPYFILE_EXCL); } catch { /* already kept */ } }
    pruneBackups(file);
  }
  const text = `${JSON.stringify(data, null, 2)}\n`;
  JSON.parse(text);
  const tmp = `${file}.${MARKER}.tmp`;
  fs.writeFileSync(tmp, text, { mode });
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, file);
}

const hookFiles = (ctx) => ({
  claude: path.join(ctx.home, '.claude', 'settings.json'),
  codex: path.join(ctx.home, '.codex', 'hooks.json'),
  cursor: path.join(ctx.home, '.cursor', 'hooks.json'),
});

function hookCommand(ctx, agent) {
  return `${JSON.stringify(ctx.nodePath)} ${JSON.stringify(path.join(installDir(ctx), `${MARKER}.js`))} hook --agent ${agent}`;
}

const isOurs = (entry) => JSON.stringify(entry || {}).includes(MARKER);

function stripOurs(list) {
  if (!Array.isArray(list)) return [];
  return list.map((entry) => {
    if (entry && Array.isArray(entry.hooks)) {
      const hooks = entry.hooks.filter((h) => !isOurs(h));
      return hooks.length ? { ...entry, hooks } : null;
    }
    return isOurs(entry) ? null : entry;
  }).filter(Boolean);
}

function guardEvents(agent) {
  return agent === 'cursor' ? ['beforeShellExecution', 'beforeReadFile'] : ['PreToolUse'];
}

function agentList(flag) {
  if (!flag || flag === 'all') return AGENTS;
  if (!AGENTS.includes(flag)) throw new Error(`unknown agent ${flag}; use claude, codex, cursor or all`);
  return [flag];
}

function hookCommands(cfg, ev) {
  return (cfg?.hooks?.[ev] || []).flatMap((e) => (Array.isArray(e?.hooks) ? e.hooks.map((h) => h?.command) : [e?.command]))
    .filter((c) => typeof c === 'string' && c.includes(MARKER));
}

// Installed means every event has our entry AND its node binary and script still exist; a hook whose node was
// removed by a version manager exits 127, which agents treat as "allow".
function hookInstalled(ctx, agent, file = hookFiles(ctx)[agent]) {
  const cfg = readJsonSafe(file);
  return guardEvents(agent).every((ev) => hookCommands(cfg, ev).some((c) => {
    const quoted = [...c.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    return quoted.length >= 2 && quoted.slice(0, 2).every((p) => fs.existsSync(p));
  }));
}

function hookPresent(ctx, agent, file = hookFiles(ctx)[agent]) {
  const cfg = readJsonSafe(file);
  return guardEvents(agent).some((ev) => hookCommands(cfg, ev).length > 0);
}

function readJsonSafe(file) {
  try { return readJson(file, null); } catch { return null; }
}

/** Copies `dest` to `<dest>.replaced-<time>-<n>`; the counter keeps two saves in one millisecond apart. Throws if it cannot. */
function saveReplaced(dest, ctx) {
  const stamp = ctx.now().toISOString().replace(/[:.]/g, '-');
  for (let n = 0; n < 1000; n += 1) {
    try {
      fs.copyFileSync(dest, `${dest}.replaced-${stamp}-${String(n).padStart(3, '0')}`, fs.constants.COPYFILE_EXCL);
      return;
    } catch (e) { if (e.code !== 'EEXIST') throw e; }
  }
  throw new Error('too many saved copies for one timestamp');
}

/** `claudeDir`: install the Claude hook into that config dir's settings.json instead of ~/.claude. */
function install(ctx, agentFlag, claudeDir) {
  fs.mkdirSync(installDir(ctx), { recursive: true });
  const dest = path.join(installDir(ctx), `${MARKER}.js`);
  if (path.resolve(__filename) !== path.resolve(dest)) {
    // A different installed guard (older, newer or hand-edited) is saved as <file>.replaced-<time>-<n> before the app's
    // copy goes in; the newest 3 are kept, so a replaced newer guard can be recovered. If the save fails, the live
    // guard is left alone and the install reports the failure (a guard that cannot be saved is not replaced).
    if (fs.existsSync(dest) && !fs.readFileSync(dest).equals(fs.readFileSync(__filename))) {
      try {
        saveReplaced(dest, ctx);
        pruneByName(dest, '.replaced-', REPLACED_KEPT);
      } catch (e) {
        return { ok: false, error: `could not save the installed guard before replacing it, so it was left in place: ${e.code || e.message}`, installed: dest, changed: [] };
      }
    }
    fs.copyFileSync(__filename, dest);
  }
  fs.chmodSync(dest, 0o755);
  const changed = [];
  const skipped = [];
  // With no agent named (or "all"), only agents whose config folder already exists get a hook file: an empty HOME
  // gets the guard script and nothing else. Naming one agent (--agent codex) creates its config on purpose.
  const everyAgent = !claudeDir && (!agentFlag || agentFlag === 'all');
  for (const agent of claudeDir ? ['claude'] : agentList(agentFlag)) {
    const file = claudeDir ? path.join(claudeDir, 'settings.json') : hookFiles(ctx)[agent];
    if (everyAgent && !fs.existsSync(path.dirname(realTarget(file)))) { skipped.push(agent); continue; }
    const cfg = readJson(file, {});
    const before = JSON.stringify(cfg);
    cfg.hooks = cfg.hooks && typeof cfg.hooks === 'object' ? cfg.hooks : {};
    if (agent === 'cursor' && cfg.version === undefined) cfg.version = 1;
    for (const ev of guardEvents(agent)) {
      const list = stripOurs(cfg.hooks[ev]);
      // Codex keeps a trust record per hook position (config.toml [hooks.state."<file>:pre_tool_use:<i>:<j>"]),
      // so the guard goes last there: putting it first would move every existing hook off its record.
      if (agent === 'cursor') list.unshift({ command: hookCommand(ctx, agent), timeout: 5 });
      else if (agent === 'codex') list.push({ matcher: '*', hooks: [{ type: 'command', command: hookCommand(ctx, agent), timeout: 5 }] });
      else list.unshift({ matcher: '*', hooks: [{ type: 'command', command: hookCommand(ctx, agent), timeout: 5 }] });
      cfg.hooks[ev] = list;
    }
    if (JSON.stringify(cfg) === before) continue;
    writeJsonAtomic(file, cfg, ctx);
    changed.push(file);
  }
  return skipped.length ? { ok: true, installed: dest, changed, skipped } : { ok: true, installed: dest, changed };
}

function uninstall(ctx, agentFlag) {
  const changed = [];
  for (const agent of agentList(agentFlag)) {
    const file = hookFiles(ctx)[agent];
    if (!fs.existsSync(file)) continue;
    const cfg = readJson(file, {});
    if (!cfg.hooks) continue;
    let touched = false;
    for (const ev of guardEvents(agent)) {
      if (!JSON.stringify(cfg.hooks[ev] || []).includes(MARKER)) continue;
      cfg.hooks[ev] = stripOurs(cfg.hooks[ev]);
      touched = true;
    }
    if (touched) { writeJsonAtomic(file, cfg, ctx); changed.push(file); }
  }
  return { ok: true, changed };
}

// ---------------------------------------------------------------- doctor

function idFor(kind, subject) {
  return `${kind}:${crypto.createHash('sha1').update(String(subject)).digest('hex').slice(0, 8)}`;
}

function finding(kind, severity, subject, title, detail, fix) {
  return { id: idFor(kind, subject), kind, severity, title, detail, fix };
}

const TMP_NAME_RE = /(cookies?)([._-].*)?\.(json|db|sqlite|txt)$|^cookies$|login[ _-]?data|chrome[_-]?logins?|^logins?\.(db|json|sqlite)$|^local[ _-]?state$|binarycookies$/i;
const TMP_DIR_RE = /^chrome[-_]?prof|^browser[-_]?profile[-_]?copy/i;

const AUTOMATION_PROFILE_RE = /playwright|puppeteer|cypress|webdriver|selenium|chromedriver|lighthouse|karma-/i;

function readHead(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(65536);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).toString('latin1');
  } catch {
    return '';
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function looksLikeCredentialStore(file) {
  const head = readHead(file);
  if (head.startsWith('SQLite format 3')) return /CREATE TABLE\s+"?(logins|cookies)"?\s*\(/i.test(head);
  if (head.startsWith('cook')) return true; // Safari binarycookies magic
  if (/^#\s*(Netscape )?HTTP Cookie File/i.test(head)) return true;
  if (/"encrypted_key"\s*:/.test(head)) return true; // Chromium Local State holds the cookie key
  return /"domain"\s*:/.test(head) && /"value"\s*:/.test(head) && /"name"\s*:/.test(head); // exported cookies JSON
}

function scanTmp(ctx) {
  const out = [];
  let budget;
  const walk = (dir, depth) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (--budget < 0) return;
      const p = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (AUTOMATION_PROFILE_RE.test(p)) continue;
        if (TMP_DIR_RE.test(e.name)) { out.push(p); continue; }
        if (depth < 6) walk(p, depth + 1);
      } else if (e.isFile()) {
        // A name alone is not enough (test_cookies.json, fortune-cookies.txt): the content must look like a
        // credential store, and live automation profiles (Playwright, Puppeteer, ...) are skipped.
        if (AUTOMATION_PROFILE_RE.test(p)) continue;
        if ((TMP_NAME_RE.test(e.name) || /\.(db|sqlite|sqlite3)$/i.test(e.name)) && looksLikeCredentialStore(p)) out.push(p);
      }
    }
  };
  for (const root of ctx.tmpRoots) { budget = 20000; walk(root, 0); }
  return [...new Set(out)].map((p) => finding('tmp-copy', 'high', p,
    'browser credential copy in a temp folder', p,
    { action: 'trash', path: p, says: 'move it to the Trash' }));
}

function rcFiles(ctx) {
  return ['.zshrc', '.zprofile', '.zshenv', '.bashrc', '.bash_profile', '.profile', '.config/fish/config.fish']
    .map((f) => path.join(ctx.home, f)).filter((f) => fs.existsSync(f));
}

function launchAgentFiles(ctx) {
  const dir = path.join(ctx.home, 'Library', 'LaunchAgents');
  try { return fs.readdirSync(dir).filter((f) => f.endsWith('.plist')).map((f) => path.join(dir, f)); } catch { return []; }
}

const COMMON_SECRET_NAMES = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'XAI_API_KEY', 'OPENROUTER_API_KEY',
  'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'HF_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'STRIPE_SECRET_KEY', 'ALPACA_API_KEY', 'ALPACA_SECRET_KEY', 'APCA_API_KEY_ID', 'APCA_API_SECRET_KEY',
];

function scanLaunchctlEnv(ctx) {
  const sources = new Map();
  for (const file of [...rcFiles(ctx), ...launchAgentFiles(ctx)]) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      // plist ProgramArguments put each word in its own <string>; join them back.
      const flat = line.includes('<string>') ? lines.slice(i, i + 4).join(' ').replace(/<\/?string>/g, ' ') : line;
      const m = flat.match(/launchctl\s+setenv\s+([A-Za-z_][A-Za-z0-9_]*)/);
      if (m && SECRET_NAME_RE.test(m[1]) && !sources.has(m[1])) sources.set(m[1], `${file}:${i + 1}`);
    });
  }
  // launchd has no command that lists setenv names, so also ask about common key names and the secret-looking
  // names in this shell's environment.
  const candidates = new Set([...sources.keys(), ...COMMON_SECRET_NAMES,
    ...Object.keys(ctx.env).filter((n) => SECRET_NAME_RE.test(n) && /^[A-Z][A-Z0-9_]*$/.test(n))]);
  const out = [];
  for (const name of candidates) {
    const r = ctx.run('/bin/launchctl', ['getenv', name]);
    const set = r.status === 0 && r.stdout.trim().length > 0; // the value itself is dropped here
    if (!set && !sources.has(name)) continue;
    const where = sources.get(name) || 'no startup file found; set by hand or by an agent';
    out.push(finding('launchctl-env', set ? 'high' : 'warn', name,
      set ? `${name} is set in the launchd environment (every process can read it)` : `${name} is set by a login script`,
      `source ${where}`,
      set ? { action: 'unsetenv', name, says: `run launchctl unsetenv ${name} (the line in ${where} sets it again at login; remove that line too)` }
        : { action: 'none', says: `remove the launchctl setenv line at ${where}` }));
  }
  return out;
}

function trashCopyFix(file, key, value, says) {
  return { action: 'set-json', path: file, key, value, says };
}

function scanAutoApprove(ctx, installed) {
  const out = [];
  const sev = (agent) => (installed[agent] ? 'warn' : 'high');
  const guardNote = (agent) => (installed[agent] ? 'credential hook installed' : 'no credential hook for this agent');

  for (const f of ['settings.json', 'settings.local.json']) {
    const file = path.join(ctx.home, '.claude', f);
    const cfg = readJsonSafe(file);
    if (cfg?.permissions?.defaultMode === 'bypassPermissions') {
      const rc = cfg.remoteControlAtStartup ? ', remote control on at startup' : '';
      out.push(finding('auto-approve', sev('claude'), `${file}#defaultMode`, 'Claude Code runs in bypassPermissions mode',
        `${file}: permissions.defaultMode${rc}; ${guardNote('claude')}`,
        trashCopyFix(file, ['permissions', 'defaultMode'], 'default', 'set permissions.defaultMode to "default" (original copied to Trash)')));
    }
  }

  const codexToml = path.join(ctx.home, '.codex', 'config.toml');
  try {
    let section = '';
    fs.readFileSync(codexToml, 'utf8').split('\n').forEach((line, i) => {
      const sec = line.match(/^\s*\[([^\]]+)\]/);
      if (sec) section = sec[1];
      const bad = line.match(/^\s*(approval_policy\s*=\s*"never"|sandbox_mode\s*=\s*"danger-full-access")/);
      if (bad) {
        const where = section ? `[${section}] ` : '';
        out.push(finding('auto-approve', sev('codex'), `${codexToml}:${i + 1}`, `Codex ${where}${bad[1].replace(/\s+/g, ' ')}`,
          `${codexToml}:${i + 1}; ${guardNote('codex')}`,
          { action: 'toml-line', path: codexToml, line: i + 1,
            replacement: /approval/.test(bad[1]) ? 'approval_policy = "on-request"' : 'sandbox_mode = "workspace-write"',
            says: `rewrite line ${i + 1} to ${/approval/.test(bad[1]) ? 'approval_policy = "on-request"' : 'sandbox_mode = "workspace-write"'} (original copied to Trash)` }));
      }
    });
  } catch { /* no codex config */ }

  const agy = path.join(ctx.home, '.gemini', 'antigravity-cli', 'settings.json');
  const agyCfg = readJsonSafe(agy);
  if (agyCfg) {
    const boolKeys = ['autoApproveTools', 'dangerouslySkipPermissions', 'skipPermissionChecks', 'skip_permission_checks'];
    for (const k of boolKeys) {
      if (agyCfg[k] === true) {
        out.push(finding('auto-approve', 'high', `${agy}#${k}`, `Antigravity ${k} is true`, `${agy}; no credential hook for this agent`,
          trashCopyFix(agy, [k], false, `set ${k} to false (original copied to Trash)`)));
      }
    }
    if (agyCfg.autoExecutionPolicy === 'always-proceed') {
      out.push(finding('auto-approve', 'high', `${agy}#autoExecutionPolicy`, 'Antigravity autoExecutionPolicy is "always-proceed"',
        `${agy}; no credential hook for this agent`, { action: 'none', says: 'change "Auto execution" in Antigravity settings' }));
    }
  }

  const gem = path.join(ctx.home, '.gemini', 'settings.json');
  const walk = (v, keyPath) => {
    if (v && typeof v === 'object') { for (const [k, c] of Object.entries(v)) walk(c, [...keyPath, k]); return; }
    const k = keyPath[keyPath.length - 1] || '';
    if (/yolo|autoAccept|approvalMode/i.test(k) && !/disable/i.test(k) && (v === true || v === 'yolo')) {
      out.push(finding('auto-approve', 'high', `${gem}#${keyPath.join('.')}`, `Gemini ${keyPath.join('.')} = ${JSON.stringify(v)}`,
        `${gem}; no credential hook for this agent`, { action: 'none', says: `change ${keyPath.join('.')} in Gemini settings` }));
    }
  };
  const gemCfg = readJsonSafe(gem);
  if (gemCfg) walk(gemCfg, []);

  // Wrappers on PATH and shell aliases.
  const FLAG_RE = /--dangerously-skip-permissions|--permission-mode[ =]bypassPermissions|--dangerously-bypass-approvals-and-sandbox|--ask-for-approval[ =]never|(?:^|\s)-a\s+never\b|danger-full-access|--always-approve|--sandbox[ =]disabled|--yolo\b|--approval-mode[ =]yolo/g;
  const seen = new Set();
  const scanFile = (file, kind) => {
    let real;
    try { real = fs.realpathSync(file); } catch { return; }
    if (seen.has(real)) return;
    seen.add(real);
    let st;
    try { st = fs.statSync(real); } catch { return; }
    if (!st.isFile() || st.size > 256 * 1024) return;
    let text;
    try {
      const head = fs.readFileSync(real);
      if (kind === 'wrapper' && !(head[0] === 0x23 && head[1] === 0x21)) return; // scripts only (#!)
      text = head.toString('utf8');
    } catch { return; }
    // Only lines that start an agent count; comments and grep checks that merely mention a flag do not.
    const lines = text.split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l) && !/\bgrep\b/.test(l) && AGENT_WORD_RE.test(l));
    const flags = [...new Set(lines.flatMap((l) => l.match(FLAG_RE) || []).map((f) => f.trim()))];
    if (!flags.length) return;
    out.push(finding('auto-approve', 'warn', real, `${kind === 'rc' ? 'shell startup file' : 'wrapper on PATH'} turns on auto-approve: ${flags.join(', ')}`,
      `${file}${file !== real ? ` -> ${real}` : ''}`,
      { action: 'none', says: 'no automatic fix: edit the flags out, or install the credential hook for that agent' }));
  };
  // Every script on PATH, not only agent-named ones; the line-level agent-word rule keeps other tools out.
  const scan = pathScripts(ctx);
  for (const s of scan.scripts) {
    if (seen.has(s.real)) continue;
    seen.add(s.real);
    const flags = autoApproveFlags(s.text);
    if (!flags.length) continue;
    out.push(finding('auto-approve', 'warn', s.real, `wrapper on PATH turns on auto-approve: ${flags.join(', ')}`,
      `${s.file}${s.file !== s.real ? ` -> ${s.real}` : ''}`,
      { action: 'none', says: 'no automatic fix: edit the flags out, or install the credential hook for that agent' }));
  }
  if (scan.skippedDirs.length) {
    out.push(finding('path-scan-capped', 'info', scan.skippedDirs.join(':'), `PATH scan stopped at ${PATH_SCAN_CAP} files`,
      `dirs not scanned: ${scan.skippedDirs.join(', ')}`, { action: 'none', says: 'shorten PATH or check those folders by hand' }));
  }
  for (const f of rcFiles(ctx)) scanFile(f, 'rc');
  return out;
}

const AUTO_APPROVE_FLAG_RE = /--dangerously-skip-permissions|--permission-mode[ =]bypassPermissions|--dangerously-bypass-approvals-and-sandbox|--ask-for-approval[ =]never|(?:^|\s)-a\s+never\b|danger-full-access|--always-approve|--sandbox[ =]disabled|--yolo\b|--approval-mode[ =]yolo/g;

/** Auto-approve flags on lines that start an agent. Comments, grep lines and case patterns (`--yolo)`) don't count. */
function autoApproveFlags(text) {
  const lines = String(text).split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l) && !/\bgrep\b/.test(l) && AGENT_WORD_RE.test(l));
  const flags = [];
  for (const l of lines) {
    for (const m of l.matchAll(AUTO_APPROVE_FLAG_RE)) {
      if (/^\s*[)|]/.test(l.slice(m.index + m[0].length))) continue; // a case pattern, not a flag passed on
      flags.push(m[0].trim());
    }
  }
  return [...new Set(flags)];
}

const PATH_SCAN_CAP = 5000;
const PATH_SCRIPT_MAX = 200 * 1024;

/**
 * One bounded pass over PATH, shared by the auto-approve and hook-coverage checks: stat each file, read 2 bytes for
 * `#!`, and read the body only for regular files under 200 KB. Dataless (iCloud) files are skipped. At most
 * PATH_SCAN_CAP files are looked at; the dirs left over are returned so doctor can say so.
 */
function pathScripts(ctx) {
  if (ctx._pathScan) return ctx._pathScan;
  const scripts = [];
  const skippedDirs = [];
  let looked = 0;
  for (const dir of ctx.pathDirs || []) {
    if (looked >= PATH_SCAN_CAP) { skippedDirs.push(dir); continue; }
    let names;
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) {
      if (looked >= PATH_SCAN_CAP) { skippedDirs.push(dir); break; }
      looked += 1;
      const file = path.join(dir, n);
      let real;
      let st;
      try { real = fs.realpathSync(file); st = fs.statSync(real); } catch { continue; }
      if (!st.isFile() || st.size > PATH_SCRIPT_MAX || st.size < 2) continue;
      if (st.blocks === 0) continue; // dataless: reading it would download it
      let fd;
      try {
        fd = fs.openSync(real, 'r');
        const two = Buffer.alloc(2);
        if (fs.readSync(fd, two, 0, 2, 0) !== 2 || two[0] !== 0x23 || two[1] !== 0x21) continue;
        const body = Buffer.alloc(st.size);
        const got = fs.readSync(fd, body, 0, st.size, 0);
        scripts.push({ file, real, text: body.subarray(0, got).toString('utf8') });
      } catch { /* unreadable */ } finally {
        if (fd !== undefined) try { fs.closeSync(fd); } catch { /* closed */ }
      }
    }
  }
  ctx._pathScan = { scripts, skippedDirs };
  return ctx._pathScan;
}

const CLAUDE_DIR_MARKERS = ['settings.json', '.claude.json', 'projects'];

function expandHomeOnly(value, home) {
  let v = String(value || '').trim().replace(/^["']|["']$/g, '');
  v = v.replace(/^~(?=\/|$)/, home).replace(/\$\{HOME\}|\$HOME\b/g, home);
  if (v.includes('$') || !v.startsWith('/')) return null;
  return path.resolve(v);
}

/**
 * Claude config dirs on this Mac: ~/.claude, each ~/.claude-* that looks like a config dir, CLAUDE_CONFIG_DIR from
 * the environment and, with scanLaunchers, CLAUDE_CONFIG_DIR=<dir> in PATH scripts and shell startup files.
 */
function claudeDirs(ctx, { scanLaunchers = false } = {}) {
  const dirs = [path.join(ctx.home, '.claude')];
  try {
    for (const n of fs.readdirSync(ctx.home)) {
      if (!n.startsWith('.claude-')) continue;
      const d = path.join(ctx.home, n);
      if (CLAUDE_DIR_MARKERS.some((m) => fs.existsSync(path.join(d, m)))) dirs.push(d);
    }
  } catch { /* no home listing */ }
  const fromEnv = ctx.env && ctx.env.CLAUDE_CONFIG_DIR ? expandHomeOnly(ctx.env.CLAUDE_CONFIG_DIR, ctx.home) : null;
  if (fromEnv) dirs.push(fromEnv);
  if (scanLaunchers) {
    const texts = pathScripts(ctx).scripts.map((s) => s.text);
    for (const f of rcFiles(ctx)) { try { texts.push(fs.readFileSync(f, 'utf8')); } catch { /* skip */ } }
    for (const t of texts) {
      for (const m of t.matchAll(/CLAUDE_CONFIG_DIR=("[^"\n]*"|'[^'\n]*'|[^\s;&|]+)/g)) {
        const d = expandHomeOnly(m[1], ctx.home);
        if (d && fs.existsSync(d)) dirs.push(d);
      }
    }
  }
  return [...new Set(dirs.map((d) => path.resolve(d)))];
}

const AGENT_WORD_RE = /claude|codex|cursor|grok|\bpool\b|gemini|agy|antigravity|hermes|kimi|crush|qwen|opencode|muse|exec|"\$@"/i;

// Shells and python run inline code with -c; node, ruby, perl and osascript with -e. `bash -e file.sh` is errexit.
const INLINE_RE = /(?:^|[\s;&|(/])(?:(python[0-9.]*|bash|sh|zsh)\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*c\b|(node|ruby|perl|osascript)\s+(?:-[a-zA-Z]*\s+)*(?:-[a-zA-Z]*e\b|--eval\b))/;

function scanInlineHooks(ctx) {
  const files = [
    path.join(ctx.home, '.claude', 'settings.json'),
    path.join(ctx.home, '.claude', 'settings.local.json'),
    path.join(ctx.home, '.codex', 'hooks.json'),
    path.join(ctx.home, '.cursor', 'hooks.json'),
    path.join(ctx.home, '.gemini', 'settings.json'),
  ];
  const out = [];
  for (const file of files) {
    const cfg = readJsonSafe(file);
    if (!cfg?.hooks || typeof cfg.hooks !== 'object') continue;
    for (const [event, list] of Object.entries(cfg.hooks)) {
      if (!Array.isArray(list)) continue;
      list.forEach((entry, i) => {
        const cmds = Array.isArray(entry?.hooks) ? entry.hooks.map((h) => h?.command) : [entry?.command];
        cmds.forEach((c, j) => {
          if (typeof c !== 'string' || !INLINE_RE.test(c)) return;
          const net = /socket|urllib|http\.client|requests\.|fetch\(|\bnc\b|curl/.test(c);
          const matcher = entry?.matcher ? ` matcher ${entry.matcher}` : '';
          out.push(finding('inline-hook', net ? 'high' : 'warn', `${file}#${event}#${i}#${j}#${c.length}`,
            `${event} hook runs an inline ${(() => { const m = c.match(INLINE_RE); return m[1] || m[2]; })()} script${net ? ' that opens network connections' : ''}`,
            `${file}: hooks.${event}[${i}]${matcher} (security tools read inline interpreters as attacks; move the script into a file)`,
            { action: 'remove-hook', path: file, event, index: i, sub: Array.isArray(entry?.hooks) ? j : null,
              says: `remove hooks.${event}[${i}] (original copied to Trash)` }));
        });
      });
    }
  }
  return out;
}

const RECORDER_RE = /screenpipe/i;

function isAppOrBinary(p) {
  try {
    const st = fs.statSync(p);
    if (st.isDirectory()) return p.endsWith('.app');
    if (!st.isFile()) return false;
    const fd = fs.openSync(p, 'r');
    const b = Buffer.alloc(4);
    fs.readSync(fd, b, 0, 4, 0);
    fs.closeSync(fd);
    return ['cffaedfe', 'cefaedfe', 'cafebabe', 'feedfacf', 'feedface'].includes(b.toString('hex'));
  } catch {
    return false;
  }
}

function scanRecorders(ctx) {
  const out = [];
  const candidates = [];
  for (const dir of ctx.appDirs) {
    try { for (const n of fs.readdirSync(dir)) if (RECORDER_RE.test(n)) candidates.push(path.join(dir, n)); } catch { /* none */ }
  }
  for (const dir of ctx.pathDirs) {
    try { for (const n of fs.readdirSync(dir)) if (RECORDER_RE.test(n)) candidates.push(path.join(dir, n)); } catch { /* none */ }
  }
  for (const p of [...new Set(candidates)]) {
    if (!isAppOrBinary(p)) continue; // scripts and broken links never carry a quarantine flag
    const r = ctx.run('/usr/bin/xattr', [p]);
    const attrs = r.status === 0 ? r.stdout : '';
    if (/com\.apple\.quarantine/.test(attrs)) continue;
    const downloaded = /kMDItemWhereFroms/.test(attrs);
    out.push(finding('recorder', downloaded ? 'high' : 'warn', p,
      downloaded ? 'screen recorder downloaded with its quarantine flag stripped' : 'screen recorder without a quarantine flag (installed by a script or package manager)',
      `${p} can record the screen and audio; Gatekeeper never checked this copy`,
      { action: 'trash', path: p, says: 'move it to the Trash' }));
  }
  for (const f of launchAgentFiles(ctx)) {
    let text = '';
    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
    if (RECORDER_RE.test(text)) {
      out.push(finding('recorder', 'warn', f, 'LaunchAgent starts a screen recorder', f,
        { action: 'none', says: `unload it with launchctl bootout gui/$(id -u) ${f}, then move the file to the Trash if you do not want it` }));
    }
  }
  return out;
}

/** Log lines from the last 7 days, from the current log and its rotated .1. */
function recentLogLines(ctx) {
  const since = ctx.now().getTime() - 7 * 86400 * 1000;
  const out = [];
  for (const f of [`${LOG_FILE}.1`, LOG_FILE]) {
    let text;
    try { text = fs.readFileSync(path.join(ctx.logDir, f), 'utf8'); } catch { continue; }
    for (const line of text.split('\n')) {
      try {
        const e = JSON.parse(line);
        if (e && Date.parse(e.at) >= since) out.push(e);
      } catch { /* skip */ }
    }
  }
  return out;
}

function recentDenials(ctx, lines = recentLogLines(ctx)) {
  const counts = {};
  for (const e of lines) if (e.denied === true) counts[e.rule] = (counts[e.rule] || 0) + 1;
  return counts;
}

/** Per-rule hit counts: block counts denials (old lines without a mode included), warn and log count by mode. */
function ruleCounts(ctx, settings, lines = recentLogLines(ctx)) {
  const rules = Object.values(RULES).map((r) => ({ id: r.id, technique: r.technique, mode: settings.modes[r.id], hits: { block: 0, warn: 0, log: 0 } }));
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));
  let pausedCalls = 0;
  for (const e of lines) {
    if (e.rule === 'pause') { pausedCalls += 1; continue; }
    const r = byId[e.rule];
    if (!r) continue;
    if (e.denied === true || e.mode === 'block') r.hits.block += 1;
    else if (e.mode === 'warn' || e.mode === 'log') r.hits[e.mode] += 1;
  }
  return { rules, pausedCalls };
}

/**
 * Rules in log or warn mode: how many times each would have blocked in the last 7 days (its log or warn lines while
 * in that mode) and how many times a person overrode it (a call it matched that ran on an approval). Suggests
 * switching to block at 3 or more hits and no overrides. Display only: nothing here changes a mode.
 */
function promotionReport(ctx, settings, lines = recentLogLines(ctx)) {
  return Object.values(RULES).filter((r) => settings.modes[r.id] === 'log' || settings.modes[r.id] === 'warn').map((r) => {
    const mine = lines.filter((e) => e.rule === r.id);
    const hits = mine.filter((e) => e.denied !== true && (e.mode === 'log' || e.mode === 'warn')).length;
    const overrides = mine.filter((e) => typeof e.approvalId === 'string').length;
    return { id: r.id, technique: r.technique, mode: settings.modes[r.id], hits, overrides, suggestion: hits >= 3 && overrides === 0 ? 'switch to block' : null };
  });
}

function formatPromotion(rows) {
  if (!rows.length) return ['promotion report: no rules are in log or warn mode'];
  const out = ['promotion report, last 7 days (display only; modes are never changed automatically):'];
  for (const r of rows) {
    out.push(`  ${r.id}  ${r.technique}  ${r.mode}  would have blocked ${r.hits}x, ${r.overrides} overrides${r.suggestion ? `  -> ${r.suggestion}` : ''}`);
  }
  return out;
}

function settingsFindings(ctx, settings) {
  const file = path.join(configDir(ctx), SETTINGS_FILE);
  const out = [];
  const none = { action: 'none', says: `edit ${file} yourself in a terminal` };
  if (settings.problems.length) {
    out.push(finding('guard-settings', 'high', `${file}#invalid`, 'credential guard settings file is invalid; only its stricter values are used',
      `${file}: ${settings.problems.join('; ')}`, none));
  }
  if (settings.downgraded.length) {
    out.push(finding('guard-settings', 'high', `${file}#downgraded`, `credential rules set below block: ${settings.downgraded.join(', ')}`,
      `${file}; these rules no longer stop the call`, none));
  }
  if (settings.pinned) {
    out.push(finding('guard-settings', 'warn', `${file}#pinned`, 'guard-config cannot be set below block; the file\'s value is ignored', file, none));
  }
  return out;
}

const LISTEN_PROC_RE = /^(node|nodejs|python[0-9.]*|deno|bun|uv)$|mcp|claude|codex|cursor|gemini/i;

/** Local agent and MCP servers listening on a TCP port; anything not on loopback is reachable from the network. */
function scanListeners(ctx) {
  let r;
  try { r = ctx.run('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']); } catch { return []; }
  if (!r || r.status !== 0) return [];
  const out = [];
  const seen = new Set();
  for (const line of String(r.stdout || '').split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 9) continue;
    const proc = cols[0].replace(/\\x20/g, ' ');
    if (!LISTEN_PROC_RE.test(proc)) continue;
    const name = cols.slice(8).join(' ').replace(/\s*\(LISTEN\)\s*$/, '');
    const at = name.lastIndexOf(':');
    if (at < 0) continue;
    const addr = name.slice(0, at);
    const port = name.slice(at + 1);
    const key = `${proc}#${addr}#${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const loopback = /^(127\.\d+\.\d+\.\d+|\[::1\]|localhost)$/.test(addr);
    out.push(finding('listener', loopback ? 'info' : 'high', key,
      loopback ? `${proc} listens on ${addr}:${port} (this Mac only)` : `${proc} listens on ${addr}:${port}, reachable from the network`,
      `pid ${cols[1]}; ${loopback ? 'loopback only' : 'an agent or MCP server bound to every interface accepts connections from other machines'}`,
      { action: 'none', says: loopback ? 'nothing to do' : 'restart that server bound to 127.0.0.1' }));
  }
  return out;
}

const BROWSER_PROFILE_DIRS = [
  'Library/Application Support/Google/Chrome', 'Library/Application Support/BraveSoftware/Brave-Browser',
  'Library/Application Support/Microsoft Edge', 'Library/Application Support/Arc', 'Library/Application Support/Firefox',
  'Library/Safari',
];

/** Agents running as the person's own macOS user can reach the person's keychain and browsers. Info only. */
function agentIdentity(ctx) {
  const agentDirs = ['.claude', '.codex', '.cursor', '.gemini'].filter((d) => fs.existsSync(path.join(ctx.home, d)));
  if (!agentDirs.length) return [];
  const personal = [path.join('Library', 'Keychains', 'login.keychain-db'), ...BROWSER_PROFILE_DIRS]
    .filter((p) => fs.existsSync(path.join(ctx.home, p)));
  if (!personal.length) return [];
  return [finding('agent-identity', 'info', ctx.home, 'agents run as the same macOS user as the person',
    `agent config (${agentDirs.join(', ')}) and the person's login keychain or browser profiles are in the same home folder`,
    { action: 'none', says: 'run unattended agents under a dedicated macOS user or on a cloud machine' })];
}

function tailscaleBinary(ctx) {
  const candidates = [...(ctx.pathDirs || []).map((d) => path.join(d, 'tailscale')),
    ...(ctx.appDirs || []).map((d) => path.join(d, 'Tailscale.app', 'Contents', 'MacOS', 'Tailscale'))];
  return candidates.find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
}

/**
 * This Mac should only connect out: Tailscale with Shields Up off, or any serve or funnel config, lets other
 * machines connect in. Skipped when Tailscale is not installed.
 */
function scanTailscale(ctx) {
  const bin = tailscaleBinary(ctx);
  if (!bin) return { status: 'not installed', findings: [] };
  const out = [];
  const run = (args) => { try { return ctx.run(bin, args); } catch { return null; } };
  const prefs = run(['debug', 'prefs']);
  let parsed = null;
  try { parsed = prefs && prefs.status === 0 ? JSON.parse(prefs.stdout) : null; } catch { parsed = null; }
  if (parsed && parsed.ShieldsUp === false) {
    out.push(finding('tailscale', 'high', 'shields-up', 'Tailscale accepts incoming connections (Shields Up is off)',
      `${bin} debug prefs: ShieldsUp false; this Mac should only connect out to other machines`,
      { action: 'none', says: 'run tailscale set --shields-up=true' }));
  }
  for (const kind of ['serve', 'funnel']) {
    const r = run([kind, 'status', '--json']);
    if (!r || r.status !== 0) continue;
    let cfg = null;
    try { cfg = JSON.parse(r.stdout || '{}'); } catch { cfg = null; }
    const active = cfg && typeof cfg === 'object' && Object.values(cfg).some((v) => v && (typeof v !== 'object' || Object.keys(v).length));
    if (active) {
      out.push(finding('tailscale', 'high', kind, `Tailscale ${kind} is set up, so other machines can connect in`,
        `${bin} ${kind} status --json is not empty; this Mac should only connect out`,
        { action: 'none', says: `run tailscale ${kind} reset` }));
    }
  }
  return { status: parsed ? 'checked' : 'installed, prefs not readable', findings: out };
}

// Codex runs a hook only once the user has trusted it; the record lives in config.toml by hook position.
function codexTrust(ctx) {
  const file = hookFiles(ctx).codex;
  const cfg = readJsonSafe(file);
  const list = cfg?.hooks?.PreToolUse || [];
  const i = list.findIndex(isOurs);
  if (i < 0) return null;
  const j = Math.max(0, (list[i].hooks || []).findIndex((h) => isOurs(h)));
  let toml = '';
  try { toml = fs.readFileSync(path.join(ctx.home, '.codex', 'config.toml'), 'utf8'); } catch { /* none */ }
  const header = `[hooks.state."${file}:pre_tool_use:${i}:${j}"]`;
  const at = toml.indexOf(header);
  if (at < 0) {
    return finding('codex-trust', 'warn', `${file}:${i}:${j}`, 'Codex has no trust record for the credential hook yet',
      `${file} PreToolUse[${i}]; Codex runs a hook only after you trust it, so check that it shows as enabled in Codex`,
      { action: 'none', says: 'start Codex and trust the mac-yolo-credential-guard hook when it asks' });
  }
  const body = toml.slice(at + header.length).split(/\n\s*\[/)[0];
  if (/^\s*enabled\s*=\s*false/m.test(body)) {
    return finding('codex-trust', 'high', `${file}:${i}:${j}`, 'Codex has the credential hook turned off',
      `${header} has enabled = false in ~/.codex/config.toml`, { action: 'none', says: 'turn the hook on in Codex\'s hook settings' });
  }
  return null;
}

function doctor(ctx) {
  const installed = Object.fromEntries(AGENTS.map((a) => [a, hookInstalled(ctx, a)]));
  const findings = [
    ...scanTmp(ctx),
    ...scanLaunchctlEnv(ctx),
    ...scanAutoApprove(ctx, installed),
    ...scanInlineHooks(ctx),
    ...scanRecorders(ctx),
  ];
  for (const agent of AGENTS) {
    const present = fs.existsSync(path.join(ctx.home, `.${agent}`));
    if (present && !installed[agent]) {
      const broken = hookPresent(ctx, agent);
      findings.push(finding('hook-missing', broken ? 'high' : 'warn', agent,
        broken ? `${agent} credential guard hook is broken (its node or script is gone, so it blocks nothing)` : `${agent} has no credential guard hook`,
        `${hookFiles(ctx)[agent]}`,
        { action: 'install', agent, says: `install the hook for ${agent}` }));
    }
  }
  // Hook coverage for every other Claude config dir (~/.claude-*, CLAUDE_CONFIG_DIR, launchers).
  const mainClaude = path.join(ctx.home, '.claude');
  for (const dir of claudeDirs(ctx, { scanLaunchers: true })) {
    if (dir === mainClaude) continue;
    const file = path.join(dir, 'settings.json');
    if (hookInstalled(ctx, 'claude', file)) continue;
    const broken = hookPresent(ctx, 'claude', file);
    findings.push(finding('hook-missing', broken ? 'high' : 'warn', dir,
      broken ? `Claude config ${dir} has a broken credential guard hook` : `Claude config ${dir} has no credential guard hook`,
      file, { action: 'install', agent: 'claude', dir, says: `install the hook into ${file}` }));
  }
  if (installed.codex) {
    const f = codexTrust(ctx);
    if (f) findings.push(f);
  }
  const settings = loadSettings(ctx);
  findings.push(...settingsFindings(ctx, settings));
  findings.push(...scanListeners(ctx));
  findings.push(...agentIdentity(ctx));
  const tailscale = scanTailscale(ctx);
  findings.push(...tailscale.findings);
  const work = readWorkFolders(ctx);
  const lines = recentLogLines(ctx);
  const counts = ruleCounts(ctx, settings, lines);
  return {
    ok: !findings.some((f) => f.severity !== 'info'),
    paused: fs.existsSync(path.join(configDir(ctx), 'PAUSE')),
    hooks: installed,
    workFolders: work.length ? `${work.length} listed` : 'none listed (opt-in)',
    denialsLast7Days: recentDenials(ctx, lines),
    rules: counts.rules,
    promotion: promotionReport(ctx, settings, lines),
    pausedCalls: counts.pausedCalls,
    tailscale: tailscale.status,
    findings,
  };
}

function formatDoctor(report) {
  const lines = [];
  if (report.paused) lines.push(`PAUSED: every agent tool call is denied until a person removes ~/.config/mac-yolo/PAUSE (${report.pausedCalls || 0} calls denied in the last 7 days)`);
  lines.push(`credential guard hooks: ${AGENTS.map((a) => `${a} ${report.hooks[a] ? 'on' : 'off'}`).join(', ')}; work folders: ${report.workFolders}`);
  const withHits = (report.rules || []).filter((r) => r.hits.block + r.hits.warn + r.hits.log > 0);
  if (withHits.length) lines.push('rule hits in the last 7 days (rule, ATT&CK technique, mode):');
  for (const r of withHits) {
    lines.push(`  ${r.id}  ${r.technique}  ${r.mode}  ${r.hits.block} blocked, ${r.hits.warn} warned, ${r.hits.log} logged`);
  }
  if (!report.findings.length) lines.push('no findings');
  for (const f of report.findings) lines.push(`[${f.severity}] ${f.id}  ${f.title}  (${f.detail})`);
  if (report.findings.length) lines.push('fix one: mac-yolo-credential-guard fix <id>   (asks first; files go to the Trash)');
  return lines.join('\n');
}

// ---------------------------------------------------------------- fix

function moveToTrash(ctx, p) {
  const trash = path.join(ctx.home, '.Trash');
  fs.mkdirSync(trash, { recursive: true });
  const stamp = ctx.now().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(trash, `${path.basename(p)} ${stamp}`);
  try {
    fs.renameSync(p, dest);
  } catch (e) {
    if (e.code !== 'EXDEV') throw e;
    fs.cpSync(p, dest, { recursive: true, preserveTimestamps: true });
    fs.rmSync(p, { recursive: true });
  }
  return dest;
}

function copyToTrash(ctx, p) {
  const trash = path.join(ctx.home, '.Trash');
  fs.mkdirSync(trash, { recursive: true });
  const stamp = ctx.now().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(trash, `${path.basename(p)} before-mac-yolo-fix ${stamp}`);
  fs.copyFileSync(p, dest);
  return dest;
}

function writeTextAtomic(linkOrFile, text) {
  const file = realTarget(linkOrFile);
  const tmp = `${file}.${MARKER}.tmp`;
  fs.writeFileSync(tmp, text, { mode: fs.statSync(file).mode & 0o777 });
  fs.renameSync(tmp, file);
}

function applyFix(ctx, f) {
  const fx = f.fix;
  switch (fx.action) {
    case 'trash':
      return { done: true, movedTo: moveToTrash(ctx, fx.path) };
    case 'unsetenv': {
      const r = ctx.run('/bin/launchctl', ['unsetenv', fx.name]);
      return { done: r.status === 0, ran: `launchctl unsetenv ${fx.name}` };
    }
    case 'set-json': {
      const backup = copyToTrash(ctx, fx.path);
      const cfg = JSON.parse(fs.readFileSync(fx.path, 'utf8'));
      let node = cfg;
      for (const k of fx.key.slice(0, -1)) node = node[k];
      node[fx.key[fx.key.length - 1]] = fx.value;
      writeTextAtomic(fx.path, `${JSON.stringify(cfg, null, 2)}\n`);
      return { done: true, backup };
    }
    case 'toml-line': {
      const backup = copyToTrash(ctx, fx.path);
      const lines = fs.readFileSync(fx.path, 'utf8').split('\n');
      const indent = lines[fx.line - 1].match(/^\s*/)[0];
      lines[fx.line - 1] = `${indent}${fx.replacement}`;
      writeTextAtomic(fx.path, lines.join('\n'));
      return { done: true, backup };
    }
    case 'remove-hook': {
      const backup = copyToTrash(ctx, fx.path);
      const cfg = JSON.parse(fs.readFileSync(fx.path, 'utf8'));
      const list = cfg.hooks[fx.event];
      if (fx.sub !== null && Array.isArray(list[fx.index]?.hooks) && list[fx.index].hooks.length > 1) list[fx.index].hooks.splice(fx.sub, 1);
      else list.splice(fx.index, 1);
      writeTextAtomic(fx.path, `${JSON.stringify(cfg, null, 2)}\n`);
      return { done: true, backup };
    }
    case 'install':
      return { done: true, ...install(ctx, fx.agent, fx.dir) };
    default:
      return { done: false, says: fx.says };
  }
}

/** ask(question) returns the user's answer string. */
function fix(ctx, id, { yes = false, ask } = {}) {
  const report = doctor(ctx);
  const f = report.findings.find((x) => x.id === id);
  if (!f) return { ok: false, error: `no finding ${id}; run doctor again` };
  if (f.fix.action === 'none') return { ok: false, id, error: `no automatic fix: ${f.fix.says}` };
  if (!yes) {
    const answer = ask ? ask(`${f.title}\nFix: ${f.fix.says}. Go ahead? [y/N] `) : '';
    if (!/^y(es)?$/i.test(String(answer).trim())) return { ok: false, id, skipped: true };
  }
  return { ok: true, id, ...applyFix(ctx, f) };
}

function askTty(question) {
  process.stdout.write(question);
  try {
    const fd = fs.openSync('/dev/tty', 'r');
    const buf = Buffer.alloc(256);
    const n = fs.readSync(fd, buf, 0, 256, null);
    fs.closeSync(fd);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return '';
  }
}

function workFolders(ctx, sub, arg) {
  const file = path.join(configDir(ctx), 'work-folders');
  if (sub === 'add') {
    if (!arg || !path.isAbsolute(arg)) throw new Error('give an absolute folder path');
    fs.mkdirSync(configDir(ctx), { recursive: true });
    if (!readWorkFolders(ctx).includes(path.resolve(arg))) fs.appendFileSync(file, `${path.resolve(arg)}\n`);
  }
  return { file, folders: readWorkFolders(ctx) };
}

// ---------------------------------------------------------------- CLI

function flagValue(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function main(argv, ctx = defaultCtx()) {
  const [cmd = 'doctor', ...rest] = argv;
  const print = (o) => process.stdout.write(`${JSON.stringify(o, null, 2)}\n`);
  if (cmd === 'hook') {
    let raw = '';
    try { raw = fs.readFileSync(0, 'utf8'); } catch { raw = ''; }
    const r = runHook(raw, flagValue(rest, '--agent'), ctx);
    if (r.stdout) process.stdout.write(r.stdout);
    if (r.stderr) process.stderr.write(r.stderr);
    return r.exitCode;
  }
  if (cmd === 'check') {
    const command = rest[0] === '--' ? rest.slice(1).join(' ') : rest.join(' ');
    const v = evaluate({ tool_name: 'Bash', tool_input: { command } }, ctx);
    print(v.deny ? v : { deny: false });
    return v.deny ? 3 : 0;
  }
  if (cmd === 'doctor') {
    const report = doctor(ctx);
    if (rest.includes('--json')) print(report);
    else process.stdout.write(`${formatDoctor(report)}\n`);
    return report.ok ? 0 : 1;
  }
  if (cmd === 'promote') {
    const rows = promotionReport(ctx, loadSettings(ctx));
    if (rest.includes('--json')) print(rows);
    else process.stdout.write(`${formatPromotion(rows).join('\n')}\n`);
    return 0;
  }
  if (cmd === 'pending') { print(listPending(ctx)); return 0; }
  if (cmd === 'approve') { print(approve(ctx, rest[0])); return 0; }
  if (cmd === 'deny') { print(denyPending(ctx, rest[0])); return 0; }
  if (cmd === 'fix') {
    const r = fix(ctx, rest.find((a) => !a.startsWith('--')), { yes: rest.includes('--yes'), ask: askTty });
    print(r);
    return r.ok ? 0 : 1;
  }
  if (cmd === 'install') {
    const r = install(ctx, flagValue(rest, '--agent'));
    print(r);
    if (!r.ok) { process.stderr.write(`mac-yolo-credential-guard: ${r.error}\n`); return 1; }
    return 0;
  }
  if (cmd === 'uninstall') { print(uninstall(ctx, flagValue(rest, '--agent'))); return 0; }
  if (cmd === 'work-folders') { print(workFolders(ctx, rest[0], rest[1])); return 0; }
  process.stderr.write('usage: mac-yolo-credential-guard [doctor [--json]|promote [--json]|pending|approve <digest>|deny <digest>|fix <id> [--yes]|hook [--agent a]|check -- <cmd>|install [--agent a|all]|uninstall [--agent a|all]|work-folders [list|add <path>]]\n');
  return /^(-h|--help|help)$/.test(cmd || '') ? 0 : 2;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  defaultCtx, normalize, evaluate, runHook, install, uninstall, doctor, formatDoctor, fix, workFolders, main, actionSummary,
  hookInstalled, listPending, approve, denyPending, promotionReport, formatPromotion, policyDigest, settingsFor, APPROVAL_TTL_MS, AGENTS, scanAutoApprove, readWorkFolders, LOG_FILE, HEARTBEAT_FILE, RULES, WHY, commandShape, logFields, summaryIsFixed, loggedTool, loggedParent, shellParse, loadSettings, hostIsOrSubdomain, parentChain, claudeDirs, autoApproveFlags,
  guardTarget, guardedPaths, whereFields, cleanGuardFields, classifyAccess, guardAccess,
};
