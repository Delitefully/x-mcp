#!/usr/bin/env node
/**
 * x-mcp — local MCP server that emulates X's hosted MCP endpoint
 * (https://api.x.com/mcp) for any MCP client.
 *
 * Transports:
 *   stdio            (default)      one JSON-RPC message per line on stdin/stdout
 *   streamable HTTP  (`http` cmd)   POST /mcp, JSON responses, Mcp-Session-Id
 *
 * Auth: OAuth 2.0 authorization-code + PKCE as a public client, loopback
 * callback, refresh-token rotation. Token lives in ~/.config/x-mcp/token.json
 * (0600) and is never read from another app's storage.
 *
 * Commands:
 *   auth [--scopes s1,s2] [--readonly] [--redirect URL] [--no-open]
 *   serve [--no-auto-login]    stdio proxy (default when no command given);
 *                              opens the X sign-in by itself when signed out
 *   http [--port 8790] [--path /mcp] [--host 127.0.0.1]
 *   tools [--json]             list tools from the live server
 *   call <tool> [json|@file]   one-shot tool call, prints the result
 *   status                     show token state
 *   logout                     delete the local token
 */

import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { spawn } from 'node:child_process';

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

const MCP_URL = process.env.X_MCP_URL || 'https://api.x.com/mcp';
const AUTHZ_ENDPOINT = process.env.X_OAUTH_AUTHORIZE_URL || 'https://x.com/i/oauth2/authorize';
const TOKEN_ENDPOINT = process.env.X_OAUTH_TOKEN_URL || 'https://api.x.com/2/oauth2/token';

// Public PKCE client shipped with the X plugin. Override with your own X app
// (then also override --redirect to one of that app's registered callbacks).
const CLIENT_ID = process.env.X_OAUTH_CLIENT_ID || 'NGdZYmo4VVp2T1BnRG55NlExOGQ6MTpjaQ';
const DEFAULT_REDIRECT = process.env.X_OAUTH_REDIRECT_URI || 'http://localhost:8787/callback';

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'x-mcp', version: '0.1.0' };

// Full scope set the X plugin requests. offline.access is what yields a
// refresh token; drop write scopes with --readonly if you only want reads.
const SCOPES_FULL = [
  'tweet.read', 'tweet.write', 'users.read', 'follows.read', 'space.read',
  'mute.read', 'like.read', 'list.read', 'list.write', 'block.read',
  'block.write', 'bookmark.read', 'bookmark.write', 'dm.read', 'dm.write',
  'calls.read', 'calls.write', 'broadcast.read', 'broadcast.write',
  'media.write', 'developer.billing.write', 'developer.write', 'offline.access',
];
const SCOPES_READONLY = [
  'tweet.read', 'users.read', 'follows.read', 'like.read', 'list.read',
  'bookmark.read', 'space.read', 'mute.read', 'block.read', 'offline.access',
];

const CFG_DIR = path.join(
  process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'),
  'x-mcp',
);
const TOKEN_FILE = path.join(CFG_DIR, 'token.json');
const TOOLS_CACHE = path.join(CFG_DIR, 'tools-cache.json');

/** Seconds from an env var, or the default when unset/invalid. */
function envSeconds(name, dflt) {
  const raw = process.env[name];
  const v = raw === undefined || raw === '' ? NaN : Number(raw);
  return Number.isFinite(v) && v >= 0 ? v : dflt;
}

// How long a sign-in waits for the browser callback, and how long `serve`
// waits after an automatic sign-in attempt before it may start another one.
const LOGIN_TIMEOUT_MS = envSeconds('X_MCP_LOGIN_TIMEOUT', 300) * 1000;
// X_MCP_AUTO_LOGIN_COOLDOWN is a test hook, deliberately undocumented.
const AUTO_LOGIN_COOLDOWN_MS = envSeconds('X_MCP_AUTO_LOGIN_COOLDOWN', 60) * 1000;

const AUTH_CMD = `node ${path.basename(process.argv[1] || 'x-mcp.mjs')} auth`;

const VERBOSE = !!process.env.X_MCP_VERBOSE;
const log = (...a) => {
  if (VERBOSE) process.stderr.write(`[x-mcp] ${a.join(' ')}\n`);
};

// ---------------------------------------------------------------------------
// small utils
// ---------------------------------------------------------------------------

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256b64url = (s) => b64url(crypto.createHash('sha256').update(s).digest());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtDuration = (ms) => (ms >= 60_000 && ms % 60_000 === 0 ? `${ms / 60_000} min` : `${ms / 1000} s`);

class AuthRequired extends Error {
  constructor(msg) {
    super(msg || 'not signed in');
    this.name = 'AuthRequired';
    this.code = -32001;
  }
}

function writeFilePrivate(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch {}
}

// ---------------------------------------------------------------------------
// token store
// ---------------------------------------------------------------------------

function loadToken() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function saveToken(tok) {
  writeFilePrivate(TOKEN_FILE, JSON.stringify(tok, null, 2));
  log('token saved', TOKEN_FILE);
}

function clearToken() {
  try { fs.unlinkSync(TOKEN_FILE); } catch {}
}

let refreshInFlight = null;

async function postTokenForm(params) {
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams(params).toString(),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok || json.error) {
    const err = new Error(
      `token endpoint ${res.status}: ${json.error || 'error'}${
        json.error_description ? ` — ${json.error_description}` : ''
      }`,
    );
    err.oauth = json;
    err.status = res.status;
    throw err;
  }
  return json;
}

/** Valid access token, refreshing when close to expiry. Single-flight. */
async function accessToken({ force = false } = {}) {
  const tok = loadToken();
  if (!tok?.access_token) {
    throw new AuthRequired(
      `not signed in — run: node ${path.basename(process.argv[1] || 'x-mcp.mjs')} auth`,
    );
  }
  const fresh = tok.expires_at && Date.now() < tok.expires_at - 60_000;
  if (fresh && !force) return tok.access_token;

  if (!tok.refresh_token) {
    throw new AuthRequired('access token expired and no refresh token — run `auth` again');
  }

  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      log('refreshing access token');
      const json = await postTokenForm({
        grant_type: 'refresh_token',
        refresh_token: tok.refresh_token,
        client_id: tok.client_id || CLIENT_ID,
      }).catch((e) => {
        // X rejected the refresh token (revoked, rotated elsewhere, expired):
        // that is signed out, not a transient failure.
        if (e.status >= 400 && e.status < 500) {
          throw new AuthRequired(`refresh rejected (${e.message}) — run \`auth\` again`);
        }
        throw e;
      });
      const next = {
        ...tok,
        ...json,
        // X rotates refresh tokens; keep whichever we were handed.
        refresh_token: json.refresh_token || tok.refresh_token,
        expires_at: json.expires_in ? Date.now() + json.expires_in * 1000 : tok.expires_at,
        obtained_at: new Date().toISOString(),
      };
      saveToken(next);
      return next.access_token;
    })().finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

// ---------------------------------------------------------------------------
// MCP over streamable HTTP
// ---------------------------------------------------------------------------

function parseMcpBody(ct, text) {
  if (!text.trim()) return [];
  if (ct.includes('text/event-stream')) {
    const out = [];
    for (const block of text.split(/\r?\n\r?\n/)) {
      const data = block
        .split(/\r?\n/)
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trimStart())
        .join('\n');
      if (!data) continue;
      try { out.push(JSON.parse(data)); } catch (e) { log('bad sse frame', e.message); }
    }
    return out;
  }
  const parsed = JSON.parse(text);
  return Array.isArray(parsed) ? parsed : [parsed];
}

/**
 * POST a JSON-RPC payload to the remote MCP endpoint.
 * Returns { messages, sessionId, status }.
 * Refreshes and retries once on 401.
 */
async function mcpPost(payload, { sessionId, protocolVersion = PROTOCOL_VERSION, retry = true } = {}) {
  const token = await accessToken();
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': protocolVersion,
    'user-agent': `x-mcp/0.1 (+node ${process.versions.node})`,
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;

  const res = await fetch(MCP_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  log('POST', MCP_URL, '->', res.status);

  if (res.status === 401 || res.status === 403) {
    await res.text().catch(() => '');
    if (retry) {
      // A rejected refresh here is signed out whatever the status was, so it
      // propagates untagged.
      await accessToken({ force: true });
      return mcpPost(payload, { sessionId, protocolVersion, retry: false });
    }
    // mcpStatus lets `serve` tell a rejected token (401) from a refusal a new
    // sign-in would not fix (403, e.g. user-not-enrolled).
    const e = new AuthRequired('remote rejected the token — run `auth` again');
    e.mcpStatus = res.status;
    throw e;
  }

  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const text = res.status === 202 || res.status === 204 ? '' : await res.text();

  if (!res.ok) {
    let detail = text;
    try {
      const j = JSON.parse(text);
      detail = j.detail || j.title || j.error_description || text;
    } catch {}
    const err = new Error(`MCP HTTP ${res.status}: ${String(detail).slice(0, 400)}`);
    err.status = res.status;
    throw err;
  }

  return {
    messages: parseMcpBody(ct, text),
    sessionId: res.headers.get('mcp-session-id') || sessionId,
    status: res.status,
  };
}

const pickResponse = (messages, id) =>
  messages.find((m) => m && m.id === id) || messages.find((m) => m && (m.result || m.error)) || null;

/**
 * One logical request against a persistent remote session.
 */
class Remote {
  constructor() {
    this.sessionId = null;
    this.protocolVersion = PROTOCOL_VERSION;
    this.nextId = 1;
    this.initialized = false;
  }

  async initialize(clientParams = this.clientParams || {}) {
    this.clientParams = clientParams;
    const payload = {
      jsonrpc: '2.0',
      id: this.nextId++,
      method: 'initialize',
      params: {
        protocolVersion: clientParams.protocolVersion || PROTOCOL_VERSION,
        capabilities: clientParams.capabilities || {},
        clientInfo: clientParams.clientInfo || CLIENT_INFO,
      },
    };
    let out;
    try {
      out = await mcpPost(payload, { sessionId: null, protocolVersion: payload.params.protocolVersion });
    } catch (e) {
      // Some servers only accept their own advertised version.
      if (!/HTTP 4\d\d/.test(e.message)) throw e;
      out = await mcpPost(payload, { sessionId: null, protocolVersion: PROTOCOL_VERSION });
    }
    this.sessionId = out.sessionId || null;
    const resp = pickResponse(out.messages, payload.id);
    if (!resp || resp.error) {
      throw new Error(`initialize failed: ${JSON.stringify(resp?.error || out.messages).slice(0, 400)}`);
    }
    this.protocolVersion = resp.result?.protocolVersion || PROTOCOL_VERSION;
    this.initialized = true;
    log('session', this.sessionId, 'protocol', this.protocolVersion);

    await this.notify('notifications/initialized', {});
    return resp.result;
  }

  async notify(method, params) {
    await mcpPost(
      { jsonrpc: '2.0', method, params },
      { sessionId: this.sessionId, protocolVersion: this.protocolVersion },
    );
  }

  async request(method, params) {
    const id = this.nextId++;
    const out = await mcpPost(
      { jsonrpc: '2.0', id, method, params },
      { sessionId: this.sessionId, protocolVersion: this.protocolVersion },
    );
    const resp = pickResponse(out.messages, id);
    if (!resp) throw new Error(`no response to ${method}`);
    if (resp.error) {
      const err = new Error(resp.error.message || 'remote error');
      err.rpc = resp.error;
      throw err;
    }
    return resp.result;
  }

  /** Forget the remote session, e.g. after signing in again. */
  reset() {
    this.sessionId = null;
    this.initialized = false;
  }

  async ensure() {
    if (!this.initialized) await this.initialize();
    return this;
  }
}

// ---------------------------------------------------------------------------
// auth: authorization code + PKCE on a loopback redirect
// ---------------------------------------------------------------------------

function openBrowser(url) {
  // X_MCP_BROWSER: a program to run with the URL instead of the default browser.
  const cmd =
    process.env.X_MCP_BROWSER ? process.env.X_MCP_BROWSER
    : process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'start'
    : 'xdg-open';
  try {
    const p = spawn(cmd, [url], { stdio: 'ignore', detached: true });
    p.on('error', () => {});
    p.unref();
  } catch {}
}

/**
 * Authorization code + PKCE on a loopback redirect: listen on the callback,
 * print the sign-in URL to stderr, open the browser, exchange the code and
 * save the token. Shared by `auth` and the automatic sign-in in `serve`.
 * Never writes to stdout.
 */
async function runLogin({
  redirect = DEFAULT_REDIRECT,
  scopes = SCOPES_FULL,
  open = true,
  timeoutMs = LOGIN_TIMEOUT_MS,
} = {}) {
  const u = new URL(redirect);
  if (!['localhost', '127.0.0.1', '::1'].includes(u.hostname)) {
    throw new Error(`redirect must be loopback, got ${u.hostname}`);
  }
  const port = Number(u.port || 80);
  const callbackPath = u.pathname || '/';

  const verifier = b64url(crypto.randomBytes(48));
  const challenge = sha256b64url(verifier);
  const state = b64url(crypto.randomBytes(16));

  const authUrl = new URL(AUTHZ_ENDPOINT);
  authUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: redirect,
    scope: scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  const code = await new Promise((resolve, reject) => {
    let timer;
    let settled = false;
    const server = http.createServer((req, res) => {
      const got = new URL(req.url, `http://${u.host}`);
      if (got.pathname !== callbackPath) {
        res.writeHead(404).end('not found');
        return;
      }
      const q = got.searchParams;
      const finish = (status, body) => {
        res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', connection: 'close' }).end(body);
      };
      if (q.get('error')) {
        finish(400, `<h1>${q.get('error')}</h1><p>${q.get('error_description') || ''}</p>`);
        settle(new Error(`${q.get('error')}: ${q.get('error_description') || ''}`));
        return;
      }
      if (q.get('state') !== state) {
        finish(400, '<h1>state mismatch</h1>');
        settle(new Error('state mismatch — possible CSRF, aborted'));
        return;
      }
      const c = q.get('code');
      if (!c) {
        finish(400, '<h1>missing code</h1>');
        settle(new Error('no authorization code in callback'));
        return;
      }
      finish(200, '<h1>x-mcp: authorized</h1><p>You can close this tab.</p>');
      settle(null, c);
    });
    // One exit path: stop the timer and free the callback port every time.
    function settle(err, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
      if (err) reject(err);
      else resolve(value);
    }
    server.on('error', (e) => {
      settle(e.code === 'EADDRINUSE'
        ? new Error(`port ${port} for ${redirect} is in use (another x-mcp sign-in running?)`)
        : e);
    });
    server.listen(port, u.hostname === 'localhost' ? '127.0.0.1' : u.hostname, () => {
      process.stderr.write(
        `\nSign in to X to authorize x-mcp.\n\n  ${authUrl}\n\n` +
          `Waiting for the callback on ${redirect} …\n`,
      );
      if (open) openBrowser(authUrl.toString());
    });
    timer = setTimeout(() => {
      settle(new Error(`timed out waiting for the OAuth callback (${fmtDuration(timeoutMs)})`));
      server.closeAllConnections?.();
    }, timeoutMs);
    timer.unref();
  });

  const json = await postTokenForm({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirect,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });

  saveToken({
    ...json,
    client_id: CLIENT_ID,
    redirect_uri: redirect,
    scope: json.scope || scopes.join(' '),
    expires_at: json.expires_in ? Date.now() + json.expires_in * 1000 : null,
    obtained_at: new Date().toISOString(),
  });
}

async function cmdAuth(argv) {
  const opts = parseFlags(argv);
  await runLogin({
    redirect: opts.redirect || DEFAULT_REDIRECT,
    scopes: opts.scopes
      ? String(opts.scopes).split(',').map((s) => s.trim()).filter(Boolean)
      : opts.readonly ? SCOPES_READONLY : SCOPES_FULL,
    open: !opts['no-open'],
  });

  process.stderr.write('Signed in. Verifying against the MCP endpoint …\n');
  const remote = new Remote();
  const init = await remote.initialize();
  const tools = await remote.request('tools/list', {});
  writeFilePrivate(TOOLS_CACHE, JSON.stringify(tools, null, 2));
  process.stderr.write(
    `OK — ${tools.tools?.length ?? 0} tools available ` +
      `(server ${init.serverInfo?.name || '?'} ${init.serverInfo?.version || ''}).\n`,
  );
}

// ---------------------------------------------------------------------------
// automatic sign-in for `serve`
// ---------------------------------------------------------------------------

const autoLoginOff = () => /^(0|false|off|no)$/i.test(process.env.X_MCP_AUTO_LOGIN || '');

/**
 * Single-flight browser sign-in. Every caller that arrives while one is
 * running awaits that same attempt (one browser window, one callback server).
 * After an attempt ends, for AUTO_LOGIN_COOLDOWN_MS no new one starts: callers
 * get an AuthRequired that says to run `auth`, so a sign-in that keeps
 * failing cannot become a loop of browser windows.
 */
function makeAutoLogin() {
  let inFlight = null;
  let lastEndedAt = -Infinity;

  return function signIn(cause) {
    if (inFlight) return inFlight;
    const since = Date.now() - lastEndedAt;
    if (since < AUTO_LOGIN_COOLDOWN_MS) {
      const wait = Math.ceil((AUTO_LOGIN_COOLDOWN_MS - since) / 1000);
      return Promise.reject(new AuthRequired(
        `${cause.message}; an automatic sign-in just ran and did not fix it — ` +
          `run \`${AUTH_CMD}\` in a terminal (next automatic try in ${wait} s)`,
      ));
    }

    const tok = loadToken();
    process.stderr.write(
      `\nx-mcp: signed out (${cause.message}).\n` +
        `Opening the X sign-in in your browser; set X_MCP_AUTO_LOGIN=0 to turn this off.\n`,
    );
    inFlight = runLogin({
      // Same callback and scopes as the session being replaced.
      redirect: tok?.redirect_uri || DEFAULT_REDIRECT,
      scopes: tok?.scope ? String(tok.scope).split(/\s+/).filter(Boolean) : SCOPES_FULL,
    })
      .then(() => {
        process.stderr.write('x-mcp: signed in, retrying.\n');
      })
      .catch((e) => {
        process.stderr.write(`x-mcp: sign-in did not complete: ${e.message}\n`);
        throw new AuthRequired(
          `signed out and the automatic sign-in did not complete (${e.message}) — ` +
            `run \`${AUTH_CMD}\` in a terminal, then retry`,
        );
      })
      .finally(() => {
        inFlight = null;
        lastEndedAt = Date.now();
      });
    return inFlight;
  };
}

// ---------------------------------------------------------------------------
// stdio proxy
// ---------------------------------------------------------------------------

async function cmdServe(argv = []) {
  const opts = parseFlags(argv);
  const autoLogin = !opts['no-auto-login'] && !autoLoginOff();
  const signIn = makeAutoLogin();
  // Signed out (no token, refresh rejected, MCP 401), and a new sign-in could fix it.
  const canSignIn = (e) => autoLogin && e instanceof AuthRequired && e.mcpStatus !== 403;

  const remote = new Remote();
  const out = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
  const errReply = (id, e) =>
    out({
      jsonrpc: '2.0',
      id,
      error: {
        code: e.code && Number.isInteger(e.code) ? e.code : -32603,
        message: e.message || String(e),
      },
    });

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

  // Serialize so responses cannot interleave and the session handshake stays ordered.
  let chain = Promise.resolve();
  const enqueue = (fn) => {
    chain = chain.then(fn).catch((e) => log('handler error', e.stack || e.message));
    return chain;
  };

  rl.on('line', (line) => {
    const text = line.trim();
    if (!text) return;

    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      out({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
      return;
    }

    enqueue(async () => {
      const batch = Array.isArray(msg);
      const msgs = batch ? msg : [msg];

      // Locally answered methods.
      const local = [];
      const forward = [];
      for (const m of msgs) {
        if (!m || typeof m !== 'object') continue;
        if (m.method === 'ping') local.push({ jsonrpc: '2.0', id: m.id, result: {} });
        else forward.push(m);
      }
      for (const l of local) if (l.id !== undefined) out(l);

      for (const m of forward) {
        const isNotification = m.id === undefined || m.id === null;
        const handle = async () => {
          if (!remote.initialized && m.method !== 'initialize') {
            await remote.initialize();
          }
          if (m.method === 'initialize') return remote.initialize(m.params || {});
          if (isNotification) {
            await remote.notify(m.method, m.params || {});
            return undefined;
          }
          const result = await remote.request(m.method, m.params || {});
          if (m.method === 'tools/list') {
            try { writeFilePrivate(TOOLS_CACHE, JSON.stringify(result, null, 2)); } catch {}
          }
          return result;
        };
        try {
          let result;
          try {
            result = await handle();
          } catch (e) {
            if (!canSignIn(e)) throw e;
            await signIn(e);
            remote.reset(); // the old session belonged to the old token
            result = await handle();
          }
          if (!isNotification) out({ jsonrpc: '2.0', id: m.id, result });
        } catch (e) {
          if (isNotification) {
            log('notification failed', m.method, e.message);
            continue;
          }
          errReply(m.id, e);
        }
      }
    });
  });

  rl.on('close', () => {
    chain.finally(() => process.exit(0));
  });

  process.stderr.write(`x-mcp → ${MCP_URL}\n`);
}

// ---------------------------------------------------------------------------
// streamable-HTTP transport for clients that cannot spawn stdio
// ---------------------------------------------------------------------------

async function cmdHttp(argv) {
  const opts = parseFlags(argv);
  const port = Number(opts.port || process.env.X_MCP_HTTP_PORT || 8790);
  const host = opts.host || '127.0.0.1';
  const mcpPath = opts.path || '/mcp';

  const remote = new Remote();
  const localSessions = new Map(); // our id -> true

  const readBody = (req) =>
    new Promise((resolve, reject) => {
      let buf = '';
      req.on('data', (c) => {
        buf += c;
        if (buf.length > 32 * 1024 * 1024) reject(new Error('body too large'));
      });
      req.on('end', () => resolve(buf));
      req.on('error', reject);
    });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname !== mcpPath) {
      res.writeHead(404, { 'content-type': 'application/json' })
        .end(JSON.stringify({ error: 'not found', hint: `POST ${mcpPath}` }));
      return;
    }

    if (req.method === 'GET') {
      res.writeHead(405, { 'content-type': 'application/json', allow: 'POST, DELETE' })
        .end(JSON.stringify({ error: 'server push not supported; use POST' }));
      return;
    }

    if (req.method === 'DELETE') {
      const sid = req.headers['mcp-session-id'];
      if (sid) localSessions.delete(sid);
      res.writeHead(200).end();
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }

    let payload;
    try {
      payload = JSON.parse(await readBody(req));
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' })
        .end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: e.message } }));
      return;
    }

    const batch = Array.isArray(payload);
    const msgs = batch ? payload : [payload];
    const responses = [];
    let sessionId = req.headers['mcp-session-id'] || null;
    let authFailure = false;

    try {
      for (const m of msgs) {
        if (!m || typeof m !== 'object') continue;
        if (m.method === 'ping') {
          responses.push({ jsonrpc: '2.0', id: m.id, result: {} });
          continue;
        }
        const isNotification = m.id === undefined || m.id === null;
        if (!remote.initialized && m.method !== 'initialize') await remote.initialize();

        if (m.method === 'initialize') {
          const result = await remote.initialize(m.params || {});
          sessionId = remote.sessionId || crypto.randomUUID();
          localSessions.set(sessionId, true);
          responses.push({ jsonrpc: '2.0', id: m.id, result });
          continue;
        }
        if (isNotification) {
          await remote.notify(m.method, m.params || {});
          continue;
        }
        const result = await remote.request(m.method, m.params || {});
        responses.push({ jsonrpc: '2.0', id: m.id, result });
      }
    } catch (e) {
      authFailure = e instanceof AuthRequired;
      for (const m of msgs) {
        if (m && typeof m === 'object' && m.id !== undefined && m.id !== null) {
          responses.push({
            jsonrpc: '2.0',
            id: m.id,
            error: {
              code: Number.isInteger(e.code) ? e.code : -32603,
              message: e.message || String(e),
            },
          });
        }
      }
    }

    const headers = { 'content-type': 'application/json' };
    if (sessionId) headers['mcp-session-id'] = sessionId;
    if (authFailure) {
      headers['www-authenticate'] = `Bearer resource_metadata="https://api.x.com/.well-known/oauth-protected-resource"`;
    }

    if (!responses.length) {
      res.writeHead(202, headers).end();
      return;
    }
    res.writeHead(authFailure ? 401 : 200, headers).end(JSON.stringify(batch ? responses : responses[0]));
  });

  server.listen(port, host, () => {
    process.stderr.write(`x-mcp HTTP listening on http://${host}:${port}${mcpPath}\n`);
  });
}

// ---------------------------------------------------------------------------
// introspection commands
// ---------------------------------------------------------------------------

async function cmdTools(argv) {
  const opts = parseFlags(argv);
  const remote = new Remote();
  await remote.initialize();
  const result = await remote.request('tools/list', {});
  writeFilePrivate(TOOLS_CACHE, JSON.stringify(result, null, 2));
  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }
  for (const t of result.tools || []) {
    const first = (t.description || '').split('\n')[0].slice(0, 110);
    process.stdout.write(`${t.name.padEnd(42)} ${first}\n`);
  }
  process.stderr.write(`\n${(result.tools || []).length} tools\n`);
}

async function cmdCall(argv) {
  const [tool, rawArgs] = argv.filter((a) => !a.startsWith('--'));
  if (!tool) throw new Error('usage: x-mcp call <tool> [json|@file]');
  let args = {};
  if (rawArgs) {
    const text = rawArgs.startsWith('@') ? fs.readFileSync(rawArgs.slice(1), 'utf8') : rawArgs;
    args = JSON.parse(text);
  }
  const remote = new Remote();
  await remote.initialize();
  const result = await remote.request('tools/call', { name: tool, arguments: args });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}

function cmdStatus() {
  const tok = loadToken();
  if (!tok) {
    process.stdout.write('not signed in\n');
    return;
  }
  const exp = tok.expires_at ? new Date(tok.expires_at).toISOString() : 'unknown';
  process.stdout.write(
    [
      `token file : ${TOKEN_FILE}`,
      `client_id  : ${tok.client_id || CLIENT_ID}`,
      `scope      : ${tok.scope || '(none)'}`,
      `expires_at : ${exp}`,
      `refresh    : ${tok.refresh_token ? 'yes' : 'no'}`,
      `endpoint   : ${MCP_URL}`,
    ].join('\n') + '\n',
  );
}

function cmdLogout() {
  clearToken();
  process.stdout.write('token removed\n');
}

// ---------------------------------------------------------------------------
// argv
// ---------------------------------------------------------------------------

function parseFlags(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = true;
    else { out[key] = next; i++; }
  }
  return out;
}

function usage() {
  process.stderr.write(
    `x-mcp — local MCP server for https://api.x.com/mcp\n\n` +
      `  x-mcp auth [--readonly] [--scopes a,b] [--redirect URL] [--no-open]\n` +
      `  x-mcp serve [--no-auto-login]   stdio proxy (default); signs in by itself when signed out\n` +
      `  x-mcp http [--port 8790] [--path /mcp] [--host 127.0.0.1]\n` +
      `  x-mcp tools [--json]\n` +
      `  x-mcp call <tool> [json|@file]\n` +
      `  x-mcp status | logout\n\n` +
      `env: X_OAUTH_CLIENT_ID, X_OAUTH_REDIRECT_URI, X_MCP_URL, X_MCP_VERBOSE=1,\n` +
      `     X_MCP_AUTO_LOGIN=0, X_MCP_LOGIN_TIMEOUT=<s>, X_MCP_BROWSER=<program>\n`,
  );
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case undefined:
    case 'serve':
      return cmdServe(rest);
    case 'auth':
      return cmdAuth(rest);
    case 'http':
      return cmdHttp(rest);
    case 'tools':
      return cmdTools(rest);
    case 'call':
      return cmdCall(rest);
    case 'status':
      return cmdStatus();
    case 'logout':
      return cmdLogout();
    case '-h':
    case '--help':
    case 'help':
      usage();
      return;
    default:
      usage();
      throw new Error(`unknown command: ${cmd}`);
  }
}

main().catch((e) => {
  if (e instanceof AuthRequired) {
    process.stderr.write(`${e.message}\n`);
    process.exit(2);
  }
  process.stderr.write(`error: ${e.message}\n`);
  if (VERBOSE) process.stderr.write(`${e.stack}\n`);
  process.exit(1);
});
