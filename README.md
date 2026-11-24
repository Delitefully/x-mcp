# x-mcp

Local MCP server that emulates X's hosted MCP endpoint (`https://api.x.com/mcp`), so any MCP client can use it. One file, zero dependencies, Node 20 or newer.

> [!NOTE]
> Unofficial project. X Corp., xAI, Anysphere and Grok Bot do not endorse it. "X" and related marks belong to their owners. It calls X's public API with your credentials, so X's Developer Agreement, policies and charges apply. No warranty.

```
MCP client ──stdio──▶ x-mcp.mjs ──HTTPS + Bearer──▶ https://api.x.com/mcp
                        │
                        └── token.json (0600)  ← PKCE login on http://localhost:8787/callback
```

## Setup

Add it to your client:

```jsonc
// Claude Desktop, Cursor, Windsurf, any JSON-configured client
{ "mcpServers": { "x": { "command": "node", "args": ["/path/to/x-mcp.mjs", "serve"] } } }
```

```bash
claude mcp add x -- node /path/to/x-mcp.mjs serve   # Claude Code
```

For HTTP-only clients, run `node x-mcp.mjs http --port 8790` and use `http://127.0.0.1:8790/mcp`.

The first tool call opens the X sign-in in your browser and saves the token to `~/.config/x-mcp/token.json`. Tokens refresh on their own. To sign in ahead of time or request read-only scopes, run `x-mcp auth [--readonly]`.

## CLI

```bash
x-mcp serve
x-mcp http [--port 8790] [--path /mcp] [--host 127.0.0.1]
x-mcp tools [--json]         # 101 tools from the server
x-mcp call <tool> [json|@file]
x-mcp auth [--readonly|--scopes a,b] [--redirect URL] [--no-open]
x-mcp status
x-mcp logout
```

```bash
node x-mcp.mjs call get_users_me '{}'
```

Tool names are X's own, not Cursor's escaped aliases. `X_MCP_VERBOSE=1` logs HTTP status and refresh events to stderr.

## Tool status (tested 2026-11-24)

| Status | Tools |
|---|---|
| Works | `get_users_me`, `get_users_me_followers`, `get_users_me_following`, `get_users_blocking`, `get_users_public_key`, `get_users_public_keys`, `get_users_timeline`, `get_users_posts`, `get_users_liked_posts`, `get_users_bookmarks`, `get_users_bookmark_folders`, `get_users_bookmarks_by_folder_id`, `search_users`, `search_spaces`, `search_communities`, `search_news`, `get_users_owned_lists`, `get_users_followed_lists`, `get_users_list_memberships`, `get_users_pinned_lists`, `get_lists_by_id`, `get_lists_followers`, `get_lists_members`, `get_lists_posts`, `get_chat_conversations`, `get_chat_conversation`, `get_chat_conversation_events`, `get_chat_message_requests`, `get_chat_message_request`, `get_chat_moderators`, `get_spaces_by_id`, `get_spaces_by_ids`, `get_spaces_by_creator_ids`, `get_spaces_posts`, `get_communities_by_id`, `get_posts_liking_users`, `list_broadcasts`, `list_scheduled_broadcasts`, `list_scheduled_calls`, `list_sources`, `get_broadcast`, `get_scheduled_call` |
| 403 `user-not-enrolled` or 503 | `get_users_by_id`, `get_users_by_username`, `get_users_by_usernames`, `get_users_mentions`, `search_posts_all`, `get_posts_counts_recent`, `get_posts_quoted_posts`, `get_posts_reposted_by`, `get_news`, `get_trends_by_woeid`, `get_broadcast_chat`, `get_usage_credits`, `get_posts_by_id`, `get_posts_by_ids` |
| Unknown | `get_source`, `get_scheduled_broadcast`, `chat_media_download`, and the 42 write tools |

Read tweets through timelines, a user's posts, bookmarks, likes or lists instead of by ID or search.

## Tests

```bash
node test/run-tests.mjs
```

Runs offline against `test/fake-x-mcp.mjs`.
