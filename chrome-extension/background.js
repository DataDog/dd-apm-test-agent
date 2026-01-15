/**
 * Background service worker for DD APM Test Agent Extension
 * Manages extension state and handles messages from content scripts
 */

// Default configuration
const DEFAULT_CONFIG = {
  enabled: false,
  testAgentUrl: 'http://localhost:8126',
  interceptLlmObs: true,
};

// Initialize storage with defaults
chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get('config');
  if (!stored.config) {
    await chrome.storage.local.set({ config: DEFAULT_CONFIG });
  }
  console.log('[DD Test Agent] Extension installed');
});

// Get current configuration
async function getConfig() {
  const stored = await chrome.storage.local.get('config');
  return stored.config || DEFAULT_CONFIG;
}

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_CONFIG') {
    getConfig().then(sendResponse);
    return true; // Keep channel open for async response
  }

  if (message.type === 'SET_CONFIG') {
    chrome.storage.local.set({ config: message.config }).then(() => {
      updateBadge();
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'PROXY_REQUEST') {
    handleProxyRequest(message.data).then(sendResponse).catch(err => {
      sendResponse({ error: err.message });
    });
    return true;
  }
});

// Proxy request to test agent
async function handleProxyRequest(requestData) {
  const config = await getConfig();

  console.log('[DD Test Agent] handleProxyRequest:', requestData.url, 'enabled:', config.enabled);

  if (!config.enabled) {
    return { shouldProxy: false };
  }

  const { url, method, headers, body } = requestData;

  // Build test agent URL - handle both relative and absolute URLs
  let pathname, search;
  try {
    // Try parsing as absolute URL first
    const originalUrl = new URL(url);
    pathname = originalUrl.pathname;
    search = originalUrl.search;
  } catch (e) {
    // Relative URL - extract path and search manually
    const questionMark = url.indexOf('?');
    if (questionMark >= 0) {
      pathname = url.substring(0, questionMark);
      search = url.substring(questionMark);
    } else {
      pathname = url;
      search = '';
    }
  }

  const testAgentUrl = new URL(config.testAgentUrl);
  const proxyUrl = `${testAgentUrl.origin}${pathname}${search}`;

  console.log('[DD Test Agent] Proxying to:', proxyUrl);

  try {
    const response = await fetch(proxyUrl, {
      method,
      headers: {
        'Content-Type': 'application/json',
        // Don't forward auth headers to localhost
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const responseText = await response.text();
    console.log('[DD Test Agent] Response status:', response.status);
    console.log('[DD Test Agent] Response text (first 500 chars):', responseText.substring(0, 500));

    // Try to parse as JSON
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch (parseErr) {
      console.error('[DD Test Agent] Failed to parse response as JSON:', parseErr);
      console.error('[DD Test Agent] Raw response:', responseText);
      return {
        shouldProxy: true,
        error: `Invalid JSON response (status ${response.status}): ${responseText.substring(0, 100)}`,
      };
    }

    return {
      shouldProxy: true,
      status: response.status,
      data: responseData,
    };
  } catch (err) {
    console.error('[DD Test Agent] Proxy request failed:', err);
    return {
      shouldProxy: true,
      error: err.message,
    };
  }
}

// Update badge based on state
async function updateBadge() {
  const config = await getConfig();

  if (config.enabled) {
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#41c464' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// Listen for storage changes to update badge
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.config) {
    updateBadge();
  }
});

// Initialize badge on startup
updateBadge();
