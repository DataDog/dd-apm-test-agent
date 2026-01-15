/**
 * Popup script for DD APM Test Agent Extension
 * Handles configuration UI
 */

const DEFAULT_CONFIG = {
  enabled: false,
  testAgentUrl: 'http://localhost:8126',
  interceptLlmObs: true,
};

// DOM elements
const enabledCheckbox = document.getElementById('enabled');
const testAgentUrlInput = document.getElementById('testAgentUrl');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

// Load configuration
async function loadConfig() {
  const stored = await chrome.storage.local.get('config');
  const config = stored.config || DEFAULT_CONFIG;

  enabledCheckbox.checked = config.enabled;
  testAgentUrlInput.value = config.testAgentUrl || DEFAULT_CONFIG.testAgentUrl;

  updateStatus(config);
}

// Save configuration
async function saveConfig() {
  const config = {
    enabled: enabledCheckbox.checked,
    testAgentUrl: testAgentUrlInput.value || DEFAULT_CONFIG.testAgentUrl,
    interceptLlmObs: true,
  };

  await chrome.storage.local.set({ config });
  updateStatus(config);
}

// Update status display
function updateStatus(config) {
  if (config.enabled) {
    statusDot.classList.add('active');
    statusText.textContent = `Proxying to ${config.testAgentUrl}`;
  } else {
    statusDot.classList.remove('active');
    statusText.textContent = 'Proxy disabled';
  }
}

// Check test agent connectivity
async function checkConnectivity() {
  const url = testAgentUrlInput.value || DEFAULT_CONFIG.testAgentUrl;
  try {
    const response = await fetch(`${url}/info`, {
      method: 'GET',
      mode: 'cors',
    });
    if (response.ok) {
      statusText.textContent = `Connected to ${url}`;
    }
  } catch (err) {
    if (enabledCheckbox.checked) {
      statusText.textContent = `Cannot reach ${url}`;
    }
  }
}

// Event listeners
enabledCheckbox.addEventListener('change', () => {
  saveConfig();
  if (enabledCheckbox.checked) {
    checkConnectivity();
  }
});

testAgentUrlInput.addEventListener('input', debounce(saveConfig, 500));
testAgentUrlInput.addEventListener('blur', () => {
  if (enabledCheckbox.checked) {
    checkConnectivity();
  }
});

// Debounce helper
function debounce(fn, delay) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn.apply(this, args), delay);
  };
}

// Initialize
loadConfig();
