/**
 * claude_intercept.mjs — Fetch interceptor for routing Anthropic API calls through the test agent gateway.
 *
 * Node: NODE_OPTIONS="--import /path/to/claude_intercept.mjs" node ...
 * Bun:  BUN_OPTIONS="--preload /path/to/claude_intercept.mjs" bun ...   (or --preload on CLI)
 *
 * Patches globalThis.fetch to rewrite requests matching Anthropic API paths to the
 * test agent gateway URL. Works in both Node and Bun runtimes.
 *
 * Environment variables:
 *   DDAPM_GATEWAY_URL       - Gateway URL (default: http://localhost:8126/claude/proxy)
 *   DDAPM_INTERCEPT_DEBUG   - "true" to enable stderr log messages
 */

const proc = typeof process !== 'undefined' ? process : undefined;
const GATEWAY_URL = (proc?.env?.DDAPM_GATEWAY_URL) || 'http://localhost:8126/claude/proxy';
const TEST_AGENT_URL = (proc?.env?.TEST_AGENT_URL) || 'http://localhost:8126/info';
const TEST_AGENT_CHECK_MS = 500; // low timeout since it should all be local
const DEBUG = ((proc?.env?.DDAPM_INTERCEPT_DEBUG) || '').toLowerCase() === 'true';

// Match URLs that look like Anthropic API calls (Messages API, token counting, etc.)
// This catches api.anthropic.com, ai-gateway.*.ddbuild.io, and custom ANTHROPIC_BASE_URL hosts.
const ANTHROPIC_PATH_PATTERN = /\/v1\/messages|\/v1\/complete/;
const ORIGIN_PATTERN = /^(https?:\/\/[^/]+)/;

function log(msg) {
  if (DEBUG && proc?.stderr) proc.stderr.write(`[ddapm] ${msg}\n`);
}

// patch fetch
const FETCH_PATCH_MARKER = Symbol.for('ddapm.fetch.patched');
if (!globalThis.fetch?.[FETCH_PATCH_MARKER]) {
  const originalFetch = globalThis.fetch;

  async function patchedFetch(input, init) {
    let url = typeof input === 'string' ? input : input?.url;

    if (DEBUG) {
      const method = init?.method || (typeof input !== 'string' && input?.method) || 'GET';
      log(`fetch ${method} ${url}`);
    }

    if (url && ANTHROPIC_PATH_PATTERN.test(url) && !url.startsWith(GATEWAY_URL)) {
      const originMatch = url.match(ORIGIN_PATTERN);
      if (originMatch) {
        // check that test agent is running to forward to test agent proxy
        const ac = new AbortController();
        const timeoutId = setTimeout(() => ac.abort(), TEST_AGENT_CHECK_MS);
        let testAgentResult;

        try {
          testAgentResult = await originalFetch.call(this, TEST_AGENT_URL, { signal: ac.signal });
        } catch (_) {
          testAgentResult = null;
        } finally {
          clearTimeout(timeoutId);
        }

        if (!testAgentResult?.ok) {
          log('Not able to reach the test agent to forward the claude request, passing the request through to the requested URL instead.');
          return originalFetch.call(this, input, init);
        }

        const originalOrigin = originMatch[1];
        const newUrl = url.replace(originalOrigin, GATEWAY_URL);
        log(`routing → ${newUrl}`);

        // Pass the original origin so the proxy knows where to forward
        const headers = new Headers(init?.headers || (typeof input !== 'string' ? input?.headers : undefined));
        headers.set('X-DDAPM-Upstream', originalOrigin);

        if (typeof input === 'string') {
          input = newUrl;
          init = { ...init, headers };
        } else {
          input = new Request(newUrl, { ...input, headers });
        }
      }
    }

    return originalFetch.call(this, input, init);
  }
  patchedFetch[FETCH_PATCH_MARKER] = true;
  globalThis.fetch = patchedFetch;

  log(`active — routing Anthropic API calls → ${GATEWAY_URL}`);
}

// patch spawn - for start, send an additional "instrumented" field to show that this file has been loaded
const CP_SPAWN_PATCH_MARKER = Symbol.for('ddapm.child_process.spawn.patched');
const child_process = require('child_process');
if (!child_process.spawn?.[CP_SPAWN_PATCH_MARKER]) {
  const origSpawn = child_process.spawn;

  function patchedSpawn (cmd, args, opts) {
    const child = origSpawn(cmd, args, opts);
    const origWrite = child.stdin.write.bind(child.stdin);
    child.stdin.write = function(data, ...rest) {
      try {
        const parsed = JSON.parse(typeof data === 'string' ? data.trim() : data);
        if (parsed?.hook_event_name === 'SessionStart') {
          parsed.lapdog_instrumented = true;
          data = JSON.stringify(parsed);
        }
      } catch {}
      return origWrite(data, ...rest);
    };
    return child;
  };

  patchedSpawn[CP_SPAWN_PATCH_MARKER] = true;
  child_process.spawn = patchedSpawn;
}
