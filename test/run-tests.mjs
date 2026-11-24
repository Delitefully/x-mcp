#!/usr/bin/env node
/**
 * End-to-end checks against the fake X MCP server: token refresh with
 * rotation, SSE parsing, session reuse, 401 retry, tool call passthrough,
 * and stdio/HTTP transport framing.
 *
 *   node test/run-tests.mjs
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.dirname(HERE);
const FAKE_PORT = 9911;
const CALLBACK_PORT = 9913;

const cfg = fs.mkdtempSync(path.join(os.tmpdir(), 'xmcptest-'));
const env = {
  ...process.env,
  XDG_CONFIG_HOME: cfg,
  X_MCP_URL: `http://127.0.0.1:${FAKE_PORT}/mcp`,
  X_OAUTH_TOKEN_URL: `http://127.0.0.1:${FAKE_PORT}/2/oauth2/token`,
  // Never reach the real X login or the user's browser from a test.
  X_OAUTH_AUTHORIZE_URL: `http://127.0.0.1:${FAKE_PORT}/i/oauth2/authorize`,
  X_OAUTH_REDIRECT_URI: `http://127.0.0.1:${CALLBACK_PORT}/callback`,
  X_MCP_BROWSER: path.join(HERE, 'fake-browser.mjs'),
  X_MCP_VERBOSE: '1',
};
delete env.X_MCP_AUTO_LOGIN;
delete env.X_MCP_LOGIN_TIMEOUT;
delete env.X_MCP_AUTO_LOGIN_COOLDOWN;

// Every stderr the proxy wrote, checked at the end for leaked tokens.
const allProxyStderr = [];


const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, fn) => {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}: ${e.message}`);
  }
};

const isPortOpen = (port) =>
  new Promise((res) => {
    const s = new net.Socket();
    s.once('connect', () => { s.destroy(); res(true); });
    s.once('error', () => res(false));
    s.connect(port, '127.0.0.1');
  });

let browserLogs = 0;
/** Fresh file the fake browser appends one line to per launch. */
const browserLog = () => path.join(cfg, `browser-${++browserLogs}.log`);
const launches = (file) =>
  fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length : 0;
const fakeState = async () => (await fetch(`http://127.0.0.1:${FAKE_PORT}/__state`)).json();

async function waitForPort(port, tries = 60) {
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise((res) => {
      const s = new net.Socket();
      s.once('connect', () => { s.destroy(); res(true); });
      s.once('error', () => res(false));
      s.connect(port, '127.0.0.1');
    });
    if (ok) return true;
    await sleep(100);
  }
  return false;
}

/**
 * Drive the stdio proxy: send messages, collect responses until all ids answered.
 * A number in `messages` pauses that many ms before the next write.
 */
function driveProxy(messages, { timeoutMs = 15000, extraEnv = {}, args = [], onResponse = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'x-mcp.mjs'), 'serve', ...args], {
      env: { ...env, ...extraEnv },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const nonJson = [];
    const want = new Set(messages.filter((m) => typeof m === 'object' && m.id !== undefined).map((m) => m.id));
    const got = new Map();
    let finished = false;
    const done = () => {
      if (finished) return;
      finished = true;
      allProxyStderr.push(err);
      resolve({ responses: got, stderr: err, nonJson });
    };

    child.stdout.on('data', (d) => {
      out += d.toString();
      let idx;
      while ((idx = out.indexOf('\n')) >= 0) {
        const line = out.slice(0, idx).trim();
        out = out.slice(idx + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { nonJson.push(line); continue; }
        got.set(msg.id, msg);
        onResponse(msg);
        want.delete(msg.id);
        if (want.size === 0) {
          child.kill();
          done();
        }
      }
    });
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('exit', () => {
      if (want.size === 0) done();
      else reject(new Error(`proxy exited with pending ids ${[...want]} stderr=${err}`));
    });

    (async () => {
      for (const m of messages) {
        if (typeof m === 'number') await sleep(m);
        else child.stdin.write(JSON.stringify(m) + '\n');
      }
    })();
    setTimeout(() => { child.kill(); reject(new Error(`timeout; stderr=${err}`)); }, timeoutMs);
  });
}

async function main() {
  const fake = spawn(process.execPath, [path.join(HERE, 'fake-x-mcp.mjs'), '--port', String(FAKE_PORT)], {
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  if (!(await waitForPort(FAKE_PORT))) throw new Error('fake server did not start');

  try {
    // ---- 1. expired token forces a refresh, rotated token is persisted ----
    console.log('\nrefresh + rotation');
    fs.mkdirSync(path.join(cfg, 'x-mcp'), { recursive: true });
    const tokenFile = path.join(cfg, 'x-mcp', 'token.json');
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: 'stale',
      refresh_token: 'refresh-1',
      expires_at: Date.now() - 1000,
      client_id: 'test-client',
      scope: 'users.read bookmark.read offline.access',
    }));

    const r1 = await driveProxy([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_users_bookmarks', arguments: { id: '1234567890' } } },
    ]);

    check('initialize returns serverInfo', () =>
      assert.equal(r1.responses.get(1).result.serverInfo.name, 'fake-x-mcp'));
    check('tools/list parsed out of SSE', () =>
      assert.deepEqual(r1.responses.get(2).result.tools.map((t) => t.name), ['get_users_bookmarks', 'get_users_me']));
    check('tools/call result passed through', () =>
      assert.match(r1.responses.get(3).result.content[0].text, /bookmark one/));

    const saved = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    check('refreshed access token persisted', () => assert.equal(saved.access_token, 'access-2'));
    check('rotated refresh token persisted', () => assert.equal(saved.refresh_token, 'refresh-2'));
    check('expiry recorded from expires_in', () => assert.ok(saved.expires_at > Date.now() + 60_000));
    check('token file mode is 0600', () =>
      assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600));

    // ---- 2. valid token: no refresh, cache written, session reused -------
    console.log('\nvalid token path');
    const r2 = await driveProxy([
      { jsonrpc: '2.0', id: 10, method: 'tools/list' }, // forces implicit initialize
    ]);
    check('implicit initialize before tools/list', () =>
      assert.equal(r2.responses.get(10).result.tools.length, 2));
    check('tools cache written', () =>
      assert.ok(fs.existsSync(path.join(cfg, 'x-mcp', 'tools-cache.json'))));
    const tok2 = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    check('no extra refresh when token is fresh', () => assert.equal(tok2.access_token, 'access-2'));

    // ---- 3. 401 mid-session triggers one forced refresh + retry ----------
    console.log('\n401 retry');
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: 'revoked',
      refresh_token: 'refresh-2',
      expires_at: Date.now() + 3600_000,
      client_id: 'test-client',
    }));
    const r3 = await driveProxy([
      { jsonrpc: '2.0', id: 20, method: 'tools/list' },
    ]);
    check('retry after 401 succeeds', () =>
      assert.equal(r3.responses.get(20).result.tools.length, 2));
    const tok3 = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    check('forced refresh advanced tokens', () => {
      assert.notEqual(tok3.access_token, 'revoked');
      assert.equal(tok3.refresh_token, 'refresh-3');
    });

    // ---- 4. auto-login off: unauthenticated gives a clean JSON-RPC error --
    console.log('\nauto-login disabled');
    fs.rmSync(tokenFile);
    for (const [label, opts] of [
      ['X_MCP_AUTO_LOGIN=0', { extraEnv: { X_MCP_AUTO_LOGIN: '0' } }],
      ['serve --no-auto-login', { args: ['--no-auto-login'] }],
    ]) {
      const log = browserLog();
      const r4 = await driveProxy([{ jsonrpc: '2.0', id: 30, method: 'tools/list' }],
        { ...opts, extraEnv: { ...opts.extraEnv, FAKE_BROWSER_LOG: log } });
      check(`${label}: auth error code -32001`, () =>
        assert.equal(r4.responses.get(30).error.code, -32001));
      check(`${label}: auth error mentions \`auth\``, () =>
        assert.match(r4.responses.get(30).error.message, /auth/));
      check(`${label}: no stale tool list served when unauthenticated`, () =>
        assert.equal(r4.responses.get(30).result, undefined));
      check(`${label}: no browser opened`, () => assert.equal(launches(log), 0));
    }

    // ---- 4a. refresh rejected (400) -> one login -> retry succeeds ---------
    console.log('\nauto-login after refresh 400');
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: 'stale-a',
      refresh_token: 'bogus-a',
      expires_at: Date.now() - 1000,
      client_id: 'test-client',
      scope: 'users.read bookmark.read offline.access',
    }));
    let log = browserLog();
    let before = await fakeState();
    const r4a = await driveProxy([
      { jsonrpc: '2.0', id: 40, method: 'tools/call', params: { name: 'get_users_bookmarks', arguments: { id: '1' } } },
    ], { extraEnv: { FAKE_BROWSER_LOG: log } });
    let after = await fakeState();
    check('call retried after login succeeds', () =>
      assert.match(r4a.responses.get(40).result.content[0].text, /bookmark one/));
    check('exactly one browser launch', () => assert.equal(launches(log), 1));
    check('exactly one authorize hit', () => assert.equal(after.authorizes - before.authorizes, 1));
    check('sign-in URL printed to stderr', () =>
      assert.match(r4a.stderr, /http:\/\/127\.0\.0\.1:9911\/i\/oauth2\/authorize\?\S*code_challenge=/));
    check('login reused the stored scope', () =>
      assert.match(r4a.stderr, /scope=users\.read\+bookmark\.read\+offline\.access&/));
    check('stdout carried JSON-RPC only', () => assert.deepEqual(r4a.nonJson, []));
    const tok4a = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    check('new token saved by the login', () => assert.equal(tok4a.refresh_token, after.refresh));
    const portAfterLogin = await isPortOpen(CALLBACK_PORT);
    check('callback port released after login', () => assert.equal(portAfterLogin, false));

    // ---- 4b. 401 from the MCP endpoint (no refresh token) -> login ---------
    console.log('\nauto-login after MCP 401');
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: 'revoked-b',
      expires_at: Date.now() + 3600_000,
      client_id: 'test-client',
    }));
    log = browserLog();
    const r4b = await driveProxy([{ jsonrpc: '2.0', id: 45, method: 'tools/list' }],
      { extraEnv: { FAKE_BROWSER_LOG: log } });
    check('401 -> login -> retry ok', () => assert.equal(r4b.responses.get(45).result.tools.length, 2));
    check('401 path: one browser launch', () => assert.equal(launches(log), 1));

    // ---- 4b2. MCP 403 whose forced refresh is rejected -> still a login ---
    console.log('\nauto-login after MCP 403 + refresh 400');
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: 'forbidden-token',
      refresh_token: 'bogus-a',
      expires_at: Date.now() + 3600_000,
      client_id: 'test-client',
    }));
    log = browserLog();
    const r4b2 = await driveProxy([{ jsonrpc: '2.0', id: 46, method: 'tools/list' }],
      { extraEnv: { FAKE_BROWSER_LOG: log } });
    check('403 + rejected refresh -> login -> retry ok', () =>
      assert.equal(r4b2.responses.get(46).result.tools.length, 2));
    check('403 + rejected refresh: one browser launch', () => assert.equal(launches(log), 1));

    // ---- 4c. concurrent calls share one login -----------------------------
    console.log('\nconcurrent calls share one login');
    fs.rmSync(tokenFile);
    log = browserLog();
    before = await fakeState();
    const r4c = await driveProxy([
      { jsonrpc: '2.0', id: 50, method: 'tools/list' },
      { jsonrpc: '2.0', id: 51, method: 'tools/call', params: { name: 'get_users_me', arguments: {} } },
      { jsonrpc: '2.0', id: 52, method: 'tools/call', params: { name: 'get_users_bookmarks', arguments: { id: '1' } } },
    ], { extraEnv: { FAKE_BROWSER_LOG: log, FAKE_BROWSER_DELAY_MS: '500' } });
    after = await fakeState();
    check('all concurrent calls succeed', () => {
      assert.equal(r4c.responses.get(50).result.tools.length, 2);
      assert.ok(r4c.responses.get(51).result);
      assert.ok(r4c.responses.get(52).result);
    });
    check('one browser launch for all of them', () => assert.equal(launches(log), 1));
    check('one authorize hit for all of them', () => assert.equal(after.authorizes - before.authorizes, 1));
    check('one sign-in prompt on stderr', () =>
      assert.equal(r4c.stderr.match(/Sign in to X/g)?.length, 1));

    // ---- 4d. login never completed -> timeout error, cooldown, retry later -
    console.log('\nauto-login timeout');
    fs.rmSync(tokenFile, { force: true });
    log = browserLog();
    const t0 = Date.now();
    let tFirst = 0;
    const r4d = await driveProxy([
      { jsonrpc: '2.0', id: 60, method: 'tools/list' },
      { jsonrpc: '2.0', id: 61, method: 'tools/list' },
      { jsonrpc: '2.0', id: 62, method: 'tools/list' },
      2500, // past the 1 s cooldown that starts when the first attempt ends
      { jsonrpc: '2.0', id: 63, method: 'tools/list' },
    ], {
      extraEnv: {
        FAKE_BROWSER_LOG: log, FAKE_BROWSER_MODE: 'ignore',
        X_MCP_LOGIN_TIMEOUT: '1', X_MCP_AUTO_LOGIN_COOLDOWN: '1',
      },
      onResponse: (msg) => { if (msg.id === 62) tFirst = Date.now() - t0; },
    });
    check('timed-out calls get -32001', () => {
      for (const id of [60, 61, 62, 63]) assert.equal(r4d.responses.get(id).error.code, -32001);
    });
    check('timeout error says it timed out and to run `auth`', () => {
      const m = r4d.responses.get(60).error.message;
      assert.match(m, /timed out/);
      assert.match(m, /x-mcp\.mjs auth/);
    });
    check('queued calls fail fast and say to run `auth`', () => {
      for (const id of [61, 62]) assert.match(r4d.responses.get(id).error.message, /x-mcp\.mjs auth/);
      assert.ok(tFirst < 2400, `first three answered after ${tFirst} ms`);
    });
    check('no tight loop: one launch within the cooldown, one after it', () =>
      assert.equal(launches(log), 2));
    check('timeout path: stdout carried JSON-RPC only', () => assert.deepEqual(r4d.nonJson, []));
    const portStillOpen = await isPortOpen(CALLBACK_PORT);
    check('callback port released after timeout', () => assert.equal(portStillOpen, false));

    // ---- 5. HTTP transport -----------------------------------------------
    console.log('\nHTTP transport');
    const live = await fakeState();
    fs.writeFileSync(tokenFile, JSON.stringify({
      access_token: live.access,
      refresh_token: live.refresh,
      expires_at: Date.now() + 3600_000,
      client_id: 'test-client',
    }));
    const httpChild = spawn(process.execPath, [path.join(ROOT, 'x-mcp.mjs'), 'http', '--port', '9912'], {
      env, stdio: ['ignore', 'ignore', 'pipe'],
    });
    await waitForPort(9912);
    const post = (body, sid) =>
      fetch('http://127.0.0.1:9912/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(sid ? { 'mcp-session-id': sid } : {}) },
        body: JSON.stringify(body),
      });

    const initRes = await post({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'h', version: '0' } },
    });
    const initBody = await initRes.json();
    const sid = initRes.headers.get('mcp-session-id');
    check('HTTP initialize returns session id', () => assert.ok(sid));
    check('HTTP initialize result', () => assert.equal(initBody.result.serverInfo.name, 'fake-x-mcp'));

    const listRes = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, sid);
    const listBody = await listRes.json();
    check('HTTP tools/list', () => assert.equal(listBody.result.tools.length, 2));

    const notifRes = await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, sid);
    check('notification answered 202', () => assert.equal(notifRes.status, 202));

    httpChild.kill();

    // ---- 6. nothing secret on stderr --------------------------------------
    console.log('\nno tokens logged');
    const stderrAll = allProxyStderr.join('\n');
    check('proxy stderr never contains a token', () => {
      assert.doesNotMatch(stderrAll, /access-\d|refresh-\d|stale-a|bogus-a|revoked-b/);
      assert.doesNotMatch(stderrAll, /test-code/);
    });
  } finally {
    fake.kill();
  }

  console.log(failures ? `\n${failures} failing` : '\nall checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
