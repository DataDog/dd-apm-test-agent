/**
 * claude_intercept.mjs — Fetch interceptor for routing Anthropic API calls through the test agent gateway.
 *
 * Loaded via: NODE_OPTIONS="--import /path/to/claude_intercept.mjs"
 *
 * Patches globalThis.fetch to rewrite requests matching api.anthropic.com to the
 * test agent gateway URL. This operates at the Node.js level before TLS, so managed
 * settings rules cannot override the routing.
 *
 * Environment variables:
 *   DDAPM_GATEWAY_URL       - Gateway URL (default: http://localhost:8126/claude/proxy)
 *   DDAPM_INTERCEPT_DEBUG   - "true" to enable stderr log messages
 */

const GATEWAY_URL = process.env.DDAPM_GATEWAY_URL || 'http://localhost:8126/claude/proxy';
const DEBUG = (process.env.DDAPM_INTERCEPT_DEBUG || '').toLowerCase() === 'true';

// Match URLs that look like Anthropic API calls (Messages API, token counting, etc.)
// This catches api.anthropic.com, ai-gateway.*.ddbuild.io, and custom ANTHROPIC_BASE_URL hosts.
const ANTHROPIC_PATH_PATTERN = /\/v1\/messages|\/v1\/complete/;
const ORIGIN_PATTERN = /^(https?:\/\/[^/]+)/;

function log(msg) {
  if (DEBUG) process.stderr.write(`[ddapm] ${msg}\n`);
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
