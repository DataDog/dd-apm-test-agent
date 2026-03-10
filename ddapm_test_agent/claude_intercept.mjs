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
const DEBUG = ((proc?.env?.DDAPM_INTERCEPT_DEBUG) || '').toLowerCase() === 'true';

// Match URLs that look like Anthropic API calls (Messages API, token counting, etc.)
// This catches api.anthropic.com, ai-gateway.*.ddbuild.io, and custom ANTHROPIC_BASE_URL hosts.
const ANTHROPIC_PATH_PATTERN = /\/v1\/messages|\/v1\/complete/;
const ORIGIN_PATTERN = /^(https?:\/\/[^/]+)/;

function log(msg) {
  if (DEBUG && proc?.stderr) proc.stderr.write(`[ddapm] ${msg}\n`);
}

const originalFetch = globalThis.fetch;

globalThis.fetch = async function patchedFetch(input, init) {
  let url = typeof input === 'string' ? input : input?.url;

  if (DEBUG) {
    const method = init?.method || (typeof input !== 'string' && input?.method) || 'GET';
    log(`fetch ${method} ${url}`);
  }

  if (url && ANTHROPIC_PATH_PATTERN.test(url) && !url.startsWith(GATEWAY_URL)) {
    const originMatch = url.match(ORIGIN_PATTERN);
    if (originMatch) {
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
};

log(`active — routing Anthropic API calls → ${GATEWAY_URL}`);
