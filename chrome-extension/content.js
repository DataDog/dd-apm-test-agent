/**
 * Content script for DD APM Test Agent Extension
 * Handles message passing between page context and extension
 *
 * Note: The interceptor.js runs in MAIN world (page context) via manifest.
 * This content script runs in ISOLATED world and bridges to the extension.
 */

console.log('[DD Test Agent] Content script loaded (message bridge)');

// Listen for messages from the injected script (MAIN world)
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;

  // Handle toggle local mode from UI inject script
  if (event.data.type === 'DD_TEST_AGENT_TOGGLE_LOCAL') {
    try {
      // Update config in background script
      const config = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
      const newConfig = { ...config, enabled: event.data.enabled };
      await chrome.runtime.sendMessage({ type: 'SET_CONFIG', config: newConfig });
      console.log('[DD Test Agent] Local mode set to:', event.data.enabled);
    } catch (err) {
      console.error('[DD Test Agent] Failed to toggle local mode:', err);
    }
    return;
  }

  if (event.data.type === 'DD_TEST_AGENT_REQUEST') {
    try {
      // Get config from background script
      const config = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });

      if (!config || !config.enabled) {
        window.postMessage({
          type: 'DD_TEST_AGENT_RESPONSE',
          id: event.data.id,
          shouldProxy: false,
        }, '*');
        return;
      }

      // Send request through background script (to avoid CORS issues)
      const result = await chrome.runtime.sendMessage({
        type: 'PROXY_REQUEST',
        data: event.data.request,
      });

      window.postMessage({
        type: 'DD_TEST_AGENT_RESPONSE',
        id: event.data.id,
        ...result,
      }, '*');
    } catch (err) {
      console.error('[DD Test Agent] Content script error:', err);
      window.postMessage({
        type: 'DD_TEST_AGENT_RESPONSE',
        id: event.data.id,
        shouldProxy: false,
        error: err.message,
      }, '*');
    }
  }
});
