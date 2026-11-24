#!/usr/bin/env node
/**
 * Stand-in for the user's browser, used through X_MCP_BROWSER in tests.
 *
 * Invoked as `fake-browser.mjs <url>`. Appends one line per launch to
 * $FAKE_BROWSER_LOG, then:
 *   FAKE_BROWSER_MODE=follow (default)  waits $FAKE_BROWSER_DELAY_MS, then GETs
 *                                       the URL and follows the redirect back
 *                                       to x-mcp's loopback callback, like a
 *                                       user clicking "Authorize"
 *   FAKE_BROWSER_MODE=ignore            does nothing (user never signs in)
 */

import fs from 'node:fs';

const url = process.argv[2];
if (process.env.FAKE_BROWSER_LOG) fs.appendFileSync(process.env.FAKE_BROWSER_LOG, 'launch\n');

if ((process.env.FAKE_BROWSER_MODE || 'follow') === 'follow') {
  const delay = Number(process.env.FAKE_BROWSER_DELAY_MS || 0);
  await new Promise((r) => setTimeout(r, delay));
  await fetch(url, { redirect: 'follow' }).then((r) => r.text()).catch(() => {});
}
