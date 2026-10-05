/**
 * claude_intercept.mjs — Fetch interceptor for routing Anthropic API calls through the test agent gateway.
 *
 * Node: NODE_OPTIONS="--import /path/to/claude_intercept.mjs" node ...
 * Bun:  BUN_OPTIONS="--preload /path/to/claude_intercept.mjs" bun ...   (or --preload on CLI)
 *
 * Patches globalThis.fetch and Bun.FetchSession.fetch to route Anthropic API
 * requests through the test agent gateway. Claude Code's Bun build uses
 * FetchSession for model requests, bypassing globalThis.fetch.
 *
 * Environment variables:
 *   DDAPM_GATEWAY_URL       - Gateway URL (default: http://localhost:8126/claude/proxy)
 *   DDAPM_INTERCEPT_DEBUG   - "true" to also send log messages to stderr
 *   DDAPM_CLAUDE_DEBUG_LOG  - Override ~/.lapdop/claude-code-debug.log
 *   LAPDOG_SESSION_TOKEN    - Correlates hook events with this instrumented Claude process
 */

import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import child_process from 'node:child_process';

const proc = typeof process !== 'undefined' ? process : undefined;
const GATEWAY_URL = (proc?.env?.DDAPM_GATEWAY_URL) || 'http://localhost:8126/claude/proxy';
const TEST_AGENT_URL = (proc?.env?.TEST_AGENT_URL) || 'http://localhost:8126/info';
const LAPDOG_URL = (proc?.env?.LAPDOG_URL) || 'http://localhost:8126';
const DEFAULT_HOOK_URL = 'http://localhost:8126/claude/hooks';
const TEST_AGENT_CHECK_MS = 500; // low timeout since it should all be local
const DEBUG = ((proc?.env?.DDAPM_INTERCEPT_DEBUG) || '').toLowerCase() === 'true';
const LAPDOG_SESSION_TOKEN = (proc?.env?.LAPDOG_SESSION_TOKEN) || '';
const DEBUG_LOG = (proc?.env?.DDAPM_CLAUDE_DEBUG_LOG) || join(homedir(), '.lapdop', 'claude-code-debug.log');

// Match URLs that look like Anthropic API calls (Messages API, token counting, etc.)
// This catches api.anthropic.com, ai-gateway.*.ddbuild.io, and custom ANTHROPIC_BASE_URL hosts.
const ANTHROPIC_PATH_PATTERN = /\/v1\/messages|\/v1\/complete/;
const ORIGIN_PATTERN = /^(https?:\/\/[^/]+)/;
const originalFetch = globalThis.fetch;

function log(msg) {
  const line = `${new Date().toISOString()} pid=${proc?.pid} ${msg}\n`;
  try {
    mkdirSync(dirname(DEBUG_LOG), { recursive: true, mode: 0o700 });
    appendFileSync(DEBUG_LOG, line, { mode: 0o600 });
  } catch (_) {
    // Diagnostics must not interrupt Claude Code.
  }
  if (DEBUG && proc?.stderr) proc.stderr.write(`[ddapm] ${msg}\n`);
}

log(`preload active runtime=${typeof Bun !== 'undefined' ? 'bun' : 'node'} gateway=${GATEWAY_URL}`);

function requestUrl(input) {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input?.url;
}

function rewriteHookCommand(command) {
  const hookUrl = `${LAPDOG_URL.replace(/\/$/, '')}/claude/hooks`;
  return command.map(arg => typeof arg === 'string' ? arg.replace(DEFAULT_HOOK_URL, hookUrl) : arg);
}

async function routeAnthropicFetch(input, init, send, label, failOpenOnError = false) {
  const url = requestUrl(input);
  if (!url || !ANTHROPIC_PATH_PATTERN.test(url) || url.startsWith(GATEWAY_URL)) {
    return send(input, init);
  }
  const originMatch = url.match(ORIGIN_PATTERN);
  if (!originMatch) return send(input, init);

  const ac = new AbortController();
  const timeoutId = setTimeout(() => ac.abort(), TEST_AGENT_CHECK_MS);
  let agentReady = false;
  try {
    agentReady = (await originalFetch(TEST_AGENT_URL, { signal: ac.signal })).ok;
  } catch (error) {
    log(`${label} agent check failed: ${error?.name || 'error'}`);
  } finally {
    clearTimeout(timeoutId);
  }
  if (!agentReady) {
    log(`${label} agent unavailable; passing request through`);
    return send(input, init);
  }

  const upstream = originMatch[1];
  const headers = new Headers(init?.headers || (typeof input !== 'string' ? input?.headers : undefined));
  headers.set('X-DDAPM-Upstream', upstream);
  const routedUrl = url.replace(upstream, GATEWAY_URL);
  const routedInput = typeof input === 'string' || input instanceof URL
    ? routedUrl
    : new Request(routedUrl, input);
  log(`${label} routing path=${new URL(url).pathname}`);
  try {
    const response = await send(routedInput, { ...init, headers });
    log(`${label} gateway response status=${response.status}`);
    return response;
  } catch (error) {
    log(`${label} gateway request failed: ${error?.name || 'error'}`);
    if (failOpenOnError) return send(input, init);
    throw error;
  }
}

if (typeof Bun !== 'undefined' && typeof Bun.FetchSession === 'function') {
  const NativeFetchSession = Bun.FetchSession;
  Bun.FetchSession = new Proxy(NativeFetchSession, {
    construct(target, args) {
      const session = Reflect.construct(target, args);
      const nativeFetch = session.fetch;
      const observedFetch = (input, init) =>
        routeAnthropicFetch(input, init, nativeFetch, 'FetchSession', true);
      return new Proxy(session, {
        get(instance, property) {
          if (property === 'fetch') return observedFetch;
          const value = Reflect.get(instance, property, instance);
          return typeof value === 'function' ? value.bind(instance) : value;
        },
      });
    },
  });
  log('FetchSession routing active');
}

// patch fetch
const FETCH_PATCH_MARKER = Symbol.for('ddapm.fetch.patched');
const seenFetchRoutes = new Set();
if (!globalThis.fetch?.[FETCH_PATCH_MARKER]) {
  async function patchedFetch(input, init) {
    const url = requestUrl(input);
    if (url && seenFetchRoutes.size < 200) {
      try {
        const parsedUrl = new URL(url);
        const route = `${parsedUrl.host}${parsedUrl.pathname}`;
        if (!seenFetchRoutes.has(route)) {
          seenFetchRoutes.add(route);
          log(`fetch route=${route}`);
        }
      } catch (_) {
        // Fetch validates malformed URLs itself.
      }
    }

    return routeAnthropicFetch(input, init, (nextInput, nextInit) => originalFetch.call(this, nextInput, nextInit), 'fetch');
  }
  patchedFetch[FETCH_PATCH_MARKER] = true;
  globalThis.fetch = patchedFetch;

  log(`active — routing Anthropic API calls → ${GATEWAY_URL}`);
}

if (typeof Bun !== 'undefined' && typeof Bun.spawn === 'function') {
  const originalBunSpawn = Bun.spawn;
  Bun.spawn = function (...args) {
    const command = Array.isArray(args[0]) ? args[0] : args[0]?.cmd;
    if (Array.isArray(command)) {
      const rewritten = rewriteHookCommand(command);
      if (rewritten.some((arg, index) => arg !== command[index])) {
        args[0] = Array.isArray(args[0]) ? rewritten : { ...args[0], cmd: rewritten };
        log('Bun.spawn Claude hook URL updated');
      }
    }
    return originalBunSpawn.apply(this, args);
  };
  log('Bun.spawn hook routing active');
}

// patch spawn - for start, send an additional "instrumented" field to show that this file has been loaded
const CP_SPAWN_PATCH_MARKER = Symbol.for('ddapm.child_process.spawn.patched');
if (!child_process.spawn?.[CP_SPAWN_PATCH_MARKER]) {
  const origSpawn = child_process.spawn;

  function patchedSpawn (cmd, args, opts) {
    if (Array.isArray(args)) {
      args = rewriteHookCommand(args);
    }
    const child = origSpawn(cmd, args, opts);
    if (!child.stdin) return child;
    const origWrite = child.stdin.write.bind(child.stdin);
    child.stdin.write = function(data, ...rest) {
      try {
        const parsed = JSON.parse(typeof data === 'string' ? data.trim() : data);
        if (parsed?.hook_event_name) {
          if (parsed.hook_event_name === 'SessionStart') log('SessionStart hook observed');
          if (parsed.hook_event_name === 'SessionStart') {
            parsed.lapdog_instrumented = true;
          }
          if (LAPDOG_SESSION_TOKEN) {
            parsed.lapdog_session_token = LAPDOG_SESSION_TOKEN;
          }
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
