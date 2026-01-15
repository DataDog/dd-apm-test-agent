# DD APM Test Agent - Chrome Extension

This Chrome extension redirects LLM Observability API requests from the Datadog UI to your local test agent, allowing you to view traces in the real Datadog interface.

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" in the top right corner
3. Click "Load unpacked" and select this `chrome-extension` directory
4. The extension icon should appear in your toolbar

## Usage

1. Click the extension icon to open the configuration popup
2. Enter your test agent URL (default: `http://localhost:8126`)
3. Toggle "Enable Proxy" to ON
4. Navigate to [LLM Observability](https://app.datadoghq.com/llm/traces) in Datadog
5. The UI will now show traces from your local test agent

## How It Works

The extension intercepts fetch requests to Datadog's Event Platform API that are related to LLM Observability (`llm_observability_stream` data source). These requests are redirected to your local test agent, which responds with trace data in the same format.

### Intercepted Endpoints

- `/api/v1/logs-analytics/list?type=llmobs` - List traces/spans
- `/api/v1/logs-analytics/aggregate?type=llmobs` - Aggregate queries
- Any request with `llm_observability_stream` in the body

## Requirements

- Chrome or Chromium-based browser
- dd-apm-test-agent running locally with the Event Platform API enabled
- Test agent must have CORS enabled for the Datadog domain

## Troubleshooting

### Requests not being intercepted

1. Check that the extension is enabled (green badge shows "ON")
2. Verify the test agent URL is correct
3. Open DevTools and check the console for `[DD Test Agent]` log messages

### CORS errors

The test agent must allow cross-origin requests from Datadog domains. This should be configured automatically.

### No traces showing

1. Verify traces are being sent to the test agent
2. Check the test agent logs for incoming requests
3. Ensure the response format matches what Datadog expects

## Development

To modify the extension:

1. Make changes to the source files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the extension card
4. Reload the Datadog page

### Files

- `manifest.json` - Extension configuration
- `background.js` - Service worker for proxying requests
- `content.js` - Content script that injects the interceptor
- `interceptor.js` - Fetch API interceptor (runs in page context)
- `popup.html/js` - Configuration UI
