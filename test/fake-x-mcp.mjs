#!/usr/bin/env node
/**
 * Test double for https://api.x.com/mcp + its OAuth token endpoint.
 *
 * Mimics the real server's observable behavior:
 *   - 401 + WWW-Authenticate when the bearer token is wrong
 *   - Mcp-Session-Id issued on initialize, required afterwards
 *   - text/event-stream responses for requests
 *   - refresh_token grant that rotates the refresh token
 *
 * Usage: node test/fake-x-mcp.mjs [--port 9911]
 */

import http from 'node:http';

const port = Number(process.argv[process.argv.indexOf('--port') + 1]) || 9911;

const state = {
  access: 'access-1',
  refresh: 'refresh-1',
  sessions: new Set(),
  refreshes: 0,
  authorizes: 0,
  calls: [],
};

const sse = (res, id, payload, extraHeaders = {}) => {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id, ...payload })}\n\n`);
  res.end();
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  let body = '';
  for await (const chunk of req) body += chunk;

  // --- test introspection -------------------------------------------------
  if (url.pathname === '/__state') {
    res.writeHead(200, { 'content-type': 'application/json' })
      .end(JSON.stringify({
        access: state.access, refresh: state.refresh, refreshes: state.refreshes,
        authorizes: state.authorizes, calls: state.calls,
      }));
    return;
  }

  // --- authorize endpoint: the user approves at once ------------------------
  if (url.pathname === '/i/oauth2/authorize') {
    state.authorizes += 1;
    const back = new URL(url.searchParams.get('redirect_uri'));
    back.searchParams.set('code', 'test-code');
    back.searchParams.set('state', url.searchParams.get('state') || '');
    res.writeHead(302, { location: back.toString() }).end();
    return;
  }

  // --- token endpoint -----------------------------------------------------
  if (url.pathname === '/2/oauth2/token') {
    const form = new URLSearchParams(body);
    const grant = form.get('grant_type');
    if (grant === 'refresh_token') {
      if (form.get('refresh_token') !== state.refresh) {
        res.writeHead(400, { 'content-type': 'application/json' })
          .end(JSON.stringify({ error: 'invalid_request', error_description: 'Value passed for the token was invalid.' }));
        return;
      }
      state.refreshes += 1;
      state.access = `access-${state.refreshes + 1}`;
      state.refresh = `refresh-${state.refreshes + 1}`; // rotation
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        token_type: 'bearer',
        access_token: state.access,
        refresh_token: state.refresh,
        expires_in: 7200,
        scope: form.get('scope') || 'users.read bookmark.read offline.access',
      }));
      return;
    }
    if (grant === 'authorization_code') {
      if (form.get('code') !== 'test-code') {
        res.writeHead(400, { 'content-type': 'application/json' })
          .end(JSON.stringify({ error: 'invalid_request', error_description: 'bad code' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        token_type: 'bearer',
        access_token: state.access,
        refresh_token: state.refresh,
        expires_in: 7200,
        scope: form.get('scope') || 'users.read bookmark.read offline.access',
      }));
      return;
    }
    res.writeHead(400).end(JSON.stringify({ error: 'unsupported_grant_type' }));
    return;
  }

  // --- MCP endpoint -------------------------------------------------------
  if (url.pathname !== '/mcp') {
    res.writeHead(404).end();
    return;
  }

  const auth = req.headers.authorization || '';
  // A token the server knows but refuses (like X's 403 user-not-enrolled).
  if (auth === 'Bearer forbidden-token') {
    res.writeHead(403, { 'content-type': 'application/problem+json' })
      .end(JSON.stringify({ title: 'Forbidden', status: 403 }));
    return;
  }
  if (auth !== `Bearer ${state.access}`) {
    res.writeHead(401, {
      'content-type': 'application/problem+json',
      'www-authenticate': 'Bearer resource_metadata="https://api.x.com/.well-known/oauth-protected-resource"',
    }).end(JSON.stringify({ title: 'Unauthorized', status: 401 }));
    return;
  }

  const msg = JSON.parse(body || '{}');
  const sid = req.headers['mcp-session-id'];

  if (msg.method === 'initialize') {
    const sessionId = 'sess-abc123';
    state.sessions.add(sessionId);
    sse(res, msg.id, {
      result: {
        protocolVersion: '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: 'fake-x-mcp', version: '1.0.0' },
      },
    }, { 'mcp-session-id': sessionId });
    return;
  }

  if (!sid || !state.sessions.has(sid)) {
    res.writeHead(400, { 'content-type': 'application/json' })
      .end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32600, message: 'missing or unknown Mcp-Session-Id' } }));
    return;
  }

  if (msg.method === 'notifications/initialized') {
    res.writeHead(202).end();
    return;
  }

  if (msg.method === 'tools/list') {
    sse(res, msg.id, {
      result: {
        tools: [
          {
            name: 'get_users_bookmarks',
            description: 'Retrieves Posts bookmarked by the authenticated user.',
            inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
          },
          {
            name: 'get_users_me',
            description: 'Retrieves details of the authenticated user.',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      },
    });
    return;
  }

  if (msg.method === 'tools/call') {
    state.calls.push(msg.params);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        content: [{ type: 'text', text: JSON.stringify({ data: [{ id: '1', text: 'bookmark one' }], meta: { result_count: 1 } }) }],
      },
    }));
    return;
  }

  res.writeHead(200, { 'content-type': 'application/json' })
    .end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `no method ${msg.method}` } }));
});

server.listen(port, '127.0.0.1', () => {
  process.stderr.write(`fake x-mcp on http://127.0.0.1:${port} (access=${state.access})\n`);
});
