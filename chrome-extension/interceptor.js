/**
 * Fetch interceptor for DD APM Test Agent Extension
 * Injected into page context to intercept LLM Observability API calls
 *
 * Strategy: We wait for other scripts (like RUM) to load and patch fetch first,
 * then we install our interceptor on top. This ensures we're last in the chain.
 */

(function () {
  'use strict';

  // Prevent double initialization
  if (window.__DD_TEST_AGENT_INTERCEPTOR_INSTALLED__) {
    console.log('[DD Test Agent] Interceptor already installed, skipping');
    return;
  }
  window.__DD_TEST_AGENT_INTERCEPTOR_INSTALLED__ = true;

  // Store native fetch immediately before anyone can patch it
  const nativeFetch = window.fetch.bind(window);

  // URLs to intercept - match all LLM Observability API endpoints
  const LLM_OBS_PATTERNS = [
    // All llm-obs-query-rewriter endpoints (list, aggregate, clusters, facet_info, facet_range_info, etc.)
    /\/api\/unstable\/llm-obs-query-rewriter\/[^?]*\??.*type=llmobs/,
    /\/api\/unstable\/llm-obs-query-rewriter\//,
    // Legacy logs-analytics endpoints with llmobs type or for llmobs data
    /\/api\/v1\/logs-analytics\/.*type=llmobs/,
    /\/api\/v1\/logs-analytics\/fetch_one/,
    // LLM Obs trace endpoint for detail view
    /\/api\/ui\/llm-obs\/v1\/trace\//,
  ];

  // Check if a URL should be intercepted
  function shouldIntercept(url, body) {
    // Skip RUM, telemetry, and other non-LLM requests early
    if (url.includes('/api/v2/rum') ||
        url.includes('/api/v2/logs') ||
        url.includes('dd-api-key=')) {
      return false;
    }

    // Log trace endpoint specifically
    if (url.includes('/llm-obs/v1/trace/')) {
      console.log('[DD Test Agent] Trace endpoint detected:', url);
    }

    // Only log potentially interesting requests
    if (url.includes('logs-analytics') || url.includes('llm') || url.includes('query')) {
      console.log('[DD Test Agent] Checking URL:', url);
    }

    // Check URL pattern
    for (const pattern of LLM_OBS_PATTERNS) {
      if (pattern.test(url)) {
        console.log('[DD Test Agent] URL matched pattern:', pattern);
        return true;
      }
    }

    // For POST requests without type in URL, check body for llm_observability_stream
    if (body) {
      try {
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        if (bodyStr.includes('llm_observability_stream')) {
          console.log('[DD Test Agent] Body contains llm_observability_stream');
          console.log('[DD Test Agent] Request URL was:', url);
          return true;
        }
      } catch (e) {
        // Ignore parse errors
      }
    }

    return false;
  }

  // Generate unique ID for request tracking
  let requestId = 0;
  function generateId() {
    return `dd-test-agent-${++requestId}-${Date.now()}`;
  }

  // Promise-based message passing to content script
  function sendToExtension(request) {
    return new Promise((resolve) => {
      const id = generateId();

      function handleResponse(event) {
        if (event.source !== window) return;
        if (event.data.type === 'DD_TEST_AGENT_RESPONSE' && event.data.id === id) {
          window.removeEventListener('message', handleResponse);
          resolve(event.data);
        }
      }

      window.addEventListener('message', handleResponse);

      // Timeout after 30 seconds
      setTimeout(() => {
        window.removeEventListener('message', handleResponse);
        resolve({ shouldProxy: false, error: 'timeout' });
      }, 30000);

      window.postMessage({
        type: 'DD_TEST_AGENT_REQUEST',
        id,
        request,
      }, '*');
    });
  }

  // Create our interceptor that wraps whatever fetch exists at install time
  function createInterceptor(fetchToWrap) {
    return async function interceptedFetch(input, init = {}) {
      // Handle various input types: string URL, Request object, or undefined
      let url = '';
      if (typeof input === 'string') {
        url = input;
      } else if (input && typeof input === 'object' && input.url) {
        url = input.url;
      }

      // If we can't determine URL, just pass through
      if (!url) {
        return nativeFetch.apply(this, arguments);
      }

      const method = init.method || (input && typeof input === 'object' ? input.method : 'GET') || 'GET';
      let body = init.body;

      // Log only query-rewriter requests for debugging
      if (url.includes('query-rewriter')) {
        console.log('[DD Test Agent] [FETCH]', method, url);
      }

      // Parse body if it's a string
      let parsedBody = null;
      if (body) {
        try {
          parsedBody = typeof body === 'string' ? JSON.parse(body) : body;
        } catch (e) {
          // Not JSON, keep as-is
        }
      }

      // Check if we should intercept this request
      if (shouldIntercept(url, parsedBody)) {
        console.log('[DD Test Agent] Intercepting request:', method, url);

        // Extra logging for trace endpoint
        if (url.includes('/trace/')) {
          console.log('[DD Test Agent] TRACE endpoint intercepted!', method, url);
        }

        try {
          const result = await sendToExtension({
            url,
            method,
            headers: init.headers || {},
            body: parsedBody,
          });

          console.log('[DD Test Agent] Extension response:', JSON.stringify(result).substring(0, 200));

          if (result.shouldProxy && !result.error) {
            console.log('[DD Test Agent] Returning proxied response, status:', result.status);

            // Create a Response object that mimics the original
            return new Response(JSON.stringify(result.data), {
              status: result.status || 200,
              statusText: 'OK',
              headers: {
                'Content-Type': 'application/json',
              },
            });
          }

          if (result.error) {
            console.warn('[DD Test Agent] Proxy error, falling back:', result.error);
          }
        } catch (err) {
          console.error('[DD Test Agent] Interceptor error:', err);
        }
      }

      // Call through to the wrapped fetch (RUM-instrumented or native)
      // Use nativeFetch to avoid any potential loops
      return nativeFetch.apply(this, arguments);
    };
  }

  // Install interceptor - wrap whatever fetch currently exists
  function installInterceptor() {
    const currentFetch = window.fetch;

    // Don't re-wrap our own interceptor
    if (currentFetch.__ddTestAgentInterceptor__) {
      return;
    }

    const interceptor = createInterceptor(currentFetch);
    interceptor.__ddTestAgentInterceptor__ = true;
    window.fetch = interceptor;

    console.log('[DD Test Agent] Fetch interceptor installed (wrapped existing fetch)');
  }

  // Install immediately
  installInterceptor();

  // Re-install after DOM is ready (in case RUM loads via script tags)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(installInterceptor, 0);
    });
  }

  // Re-install after window load (catches late-loading scripts)
  window.addEventListener('load', () => {
    setTimeout(installInterceptor, 100);
  });

  // Also poll periodically to catch any dynamic script loading
  let pollCount = 0;
  const pollInterval = setInterval(() => {
    installInterceptor();
    pollCount++;
    // Stop polling after 5 seconds
    if (pollCount > 50) {
      clearInterval(pollInterval);
    }
  }, 100);

  // Also intercept XMLHttpRequest in case the UI uses that instead of fetch
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._ddMethod = method;
    this._ddUrl = String(url);
    // Log only query-rewriter requests
    if (this._ddUrl.includes('query-rewriter')) {
      console.log('[DD Test Agent] [XHR]', method, this._ddUrl);
    }
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.send = function(body) {
    const url = this._ddUrl || '';
    const method = this._ddMethod || 'GET';

    if (shouldIntercept(url, body)) {
      console.log('[DD Test Agent] Intercepting XHR request:', method, url);

      // For XHR, we need to handle the response differently
      const xhr = this;

      sendToExtension({
        url,
        method,
        headers: {},
        body: body ? JSON.parse(body) : null,
      }).then(result => {
        console.log('[DD Test Agent] XHR extension response:', JSON.stringify(result, null, 2));
        if (result.shouldProxy && !result.error) {
          console.log('[DD Test Agent] Returning proxied XHR response, status:', result.status);

          // Override response properties
          Object.defineProperty(xhr, 'responseText', { value: JSON.stringify(result.data), writable: false });
          Object.defineProperty(xhr, 'response', { value: JSON.stringify(result.data), writable: false });
          Object.defineProperty(xhr, 'status', { value: result.status || 200, writable: false });
          Object.defineProperty(xhr, 'readyState', { value: 4, writable: false });
          Object.defineProperty(xhr, 'statusText', { value: 'OK', writable: false });

          // Trigger events in correct order
          xhr.dispatchEvent(new ProgressEvent('loadstart'));
          xhr.dispatchEvent(new ProgressEvent('progress'));
          xhr.dispatchEvent(new ProgressEvent('load'));
          xhr.dispatchEvent(new ProgressEvent('loadend'));
          return;
        }

        console.log('[DD Test Agent] Falling back to original XHR because:',
          !result.shouldProxy ? 'shouldProxy is false' : `error: ${result.error}`);
        // Fall back to original send
        originalXHRSend.apply(xhr, [body]);
      }).catch((err) => {
        console.error('[DD Test Agent] XHR catch error:', err);
        originalXHRSend.apply(xhr, [body]);
      });

      return;
    }

    return originalXHRSend.apply(this, [body]);
  };

  // Listen for toggle messages from UI inject script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data.type === 'DD_TEST_AGENT_TOGGLE_LOCAL') {
      console.log('[DD Test Agent] Local mode toggled:', event.data.enabled);
      // The extension popup controls the actual enabled state,
      // but we can use this for UI feedback
      window.postMessage({
        type: 'DD_TEST_AGENT_LOCAL_MODE_STATE',
        enabled: event.data.enabled
      }, '*');
    }
  });

  console.log('[DD Test Agent] Fetch + XHR interceptor initialized');
})();
