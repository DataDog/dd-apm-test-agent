
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>APM Test Agent Checks</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/default.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
    <style>
        body { font-family: sans-serif; }
        #checks, #results { list-style-type: none; padding: 0; }
        .check, .result { border: 1px solid #ccc; margin: 5px; padding: 10px; }
        .check { display: flex; align-items: center; }
        .check input { margin-right: 10px; }
        .passed { background-color: #eaffea; }
        .failed { background-color: #ffeaea; }
        .traces { margin-top: 10px; }
        summary { cursor: pointer; }
        nav { margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>APM Test Agent Checks</h1>
    <nav id="nav"></nav>
    <ul id="checks"></ul>

    <h2>Results</h2>
    <ul id="results"></ul>

    <script>
        let checksByCategory = {};
        let selectedCategory = 'all';

        function renderNav() {
            const nav = document.getElementById('nav');
            nav.innerHTML = ''; // Clear existing nav
            const allLink = document.createElement('a');
            allLink.href = '#';
            allLink.textContent = 'All';
            allLink.onclick = () => selectCategory('all');
            nav.appendChild(allLink);

            for (const category in checksByCategory) {
                nav.appendChild(document.createTextNode(' | '));
                const categoryLink = document.createElement('a');
                categoryLink.href = '#';
                categoryLink.textContent = category;
                categoryLink.onclick = () => selectCategory(category);
                nav.appendChild(categoryLink);
            }
            
            nav.appendChild(document.createTextNode(' | '));
            const resetButton = document.createElement('button');
            resetButton.textContent = 'Reset Checks';
            resetButton.onclick = resetAllChecks;
            nav.appendChild(resetButton);
        }

        async function resetAllChecks() {
            if (confirm('Are you sure you want to reset all check results?')) {
                try {
                    await fetch('/test/session/clear-all-checks', { method: 'GET' });
                    location.reload();
                } catch (error) {
                    console.error('Error resetting checks:', error);
                }
            }
        }

        function selectCategory(category) {
            selectedCategory = category;
            renderChecks();
            fetchResults(); // Re-fetch results for the new category
        }

        function renderChecks() {
            const ul = document.getElementById('checks');
            ul.innerHTML = '';
            const checksToRender = selectedCategory === 'all'
                ? Object.values(checksByCategory).flat()
                : checksByCategory[selectedCategory] || [];

            for (const check of checksToRender) {
                const li = document.createElement('li');
                li.className = 'check';

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = check.enabled;
                checkbox.onchange = () => toggleCheck(check.name, checkbox.checked);

                li.appendChild(checkbox);
                li.appendChild(document.createTextNode(`[${check.team}] ${check.name}`));

                ul.appendChild(li);
            }
        }

        async function fetchChecks() {
            try {
                const response = await fetch('/checks');
                const checks = await response.json();
                checksByCategory = checks.reduce((acc, check) => {
                    if (!acc[check.category]) {
                        acc[check.category] = [];
                    }
                    acc[check.category].push(check);
                    return acc;
                }, {});
                renderNav();
                renderChecks();
            } catch (error) {
                console.error('Error fetching checks:', error);
            }
        }

        async function toggleCheck(checkName, enabled) {
            const url = enabled ? '/checks/enable' : `/checks/disable/${checkName}`;
            try {
                await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ check_name: checkName }),
                });
            } catch (error) {
                console.error('Error toggling check:', error);
            }
        }

        async function viewSourceInPlace(detailsElement, checkName) {
            if (detailsElement.open && !detailsElement.dataset.sourceLoaded) {
                const codeElement = detailsElement.querySelector('code');
                codeElement.textContent = 'Loading...';
                try {
                    const response = await fetch(`/checks/source/${checkName}`);
                    const data = await response.json();
                    codeElement.textContent = data.source_code;
                    hljs.highlightElement(codeElement);
                    detailsElement.dataset.sourceLoaded = 'true';
                } catch (error) {
                    console.error('Error fetching source:', error);
                    codeElement.textContent = 'Error loading source.';
                }
            }
        }

        function createTraceList(title, traces) {
            if (traces.length === 0) {
                return document.createDocumentFragment();
            }

            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.innerHTML = `<strong>${title} (${traces.length})</strong>`;
            details.appendChild(summary);

            const ul = document.createElement('ul');
            traces.forEach(trace => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                const traceId = typeof trace === 'object' ? trace.id : trace;
                const reason = typeof trace === 'object' ? trace.reason : null;

                const failingTags = reason
                    ? [...new Set(reason.split(';').map(s => s.trim().split(' ')[1].replace(/'/g, '')))]
                    : [];
                const failingTagsParam = failingTags.length > 0 ? `?failing_tags=${failingTags.join(',')}` : '';

                a.href = `/test/trace/${traceId}${failingTagsParam}`;
                a.target = '_blank';
                a.textContent = traceId;
                li.appendChild(a);
                if (reason) {
                    li.appendChild(document.createTextNode(` - ${reason}`));
                }
                ul.appendChild(li);
            });
            details.appendChild(ul);

            const fragment = document.createDocumentFragment();
            fragment.appendChild(details);
            return fragment;
        }

        async function fetchResults() {
            try {
                const response = await fetch('/check-results');
                const results = await response.json();
                const ul = document.getElementById('results');
                ul.innerHTML = '';
                for (const [checkName, result] of Object.entries(results)) {
                    if (selectedCategory !== 'all' && result.category !== selectedCategory) {
                        continue;
                    }
                    const li = document.createElement('li');
                    li.className = 'result ' + (result.Failed_Checks > 0 ? 'failed' : 'passed');

                    const strong = document.createElement('strong');
                    strong.textContent = `[${result.team}] ${checkName}`;
                    li.appendChild(strong);

                    li.appendChild(document.createTextNode(`: ${result.Passed_Checks} passed, ${result.Failed_Checks} failed`));

                    const p = document.createElement('p');
                    p.textContent = result.description;
                    li.appendChild(p);

                    const tracesDiv = document.createElement('div');
                    tracesDiv.className = 'traces';
                    tracesDiv.appendChild(createTraceList('Passing Traces', result.passed_traces));
                    tracesDiv.appendChild(createTraceList('Failing Traces', result.failed_traces));
                    li.appendChild(tracesDiv);

                    const details = document.createElement('details');
                    details.ontoggle = () => viewSourceInPlace(details, checkName);
                    const summary = document.createElement('summary');
                    summary.textContent = 'View Source';
                    details.appendChild(summary);

                    const pre = document.createElement('pre');
                    const code = document.createElement('code');
                    code.className = 'python';
                    pre.appendChild(code);
                    details.appendChild(pre);
                    li.appendChild(details);

                    ul.appendChild(li);
                }
            } catch (error) {
                console.error('Error fetching results:', error);
            }
        }

        fetchChecks();
        setInterval(() => {
            const isAnySourceViewOpen = document.querySelector('#results details[open]');
            if (!isAnySourceViewOpen) {
                fetchResults();
            }
        }, 2000);
    </script>
</body>
</html>
"""


def render_trace_html(trace, failing_tags=None, config=None):
    if not trace:
        return "<html><body><h1>No spans in trace.</h1></body></html>"

    trace_id = trace[0].get("trace_id")
    datadog_url = f"https://app.datadoghq.com/apm/trace/{trace_id}" if trace_id else "#"

    if failing_tags is None:
        failing_tags = []

    failing_paths = set(failing_tags)

    def highlight_if_failing(path):
        return 'style="background-color: #ff4d4d;"' if path in failing_paths else ""

    config_html = ""
    if config:
        env_html = ""
        if "env" in config and config["env"]:
            sorted_env = "".join(
                f'<li><strong>{k}:</strong> {v}</li>'
                for k, v in sorted(config["env"].items())
            )
            env_html = f"""
            <div class="config">
                <h4>Environment Variables</h4>
                <ul class="tag-list">{sorted_env}</ul>
            </div>
            """

        headers_html = ""
        if "headers" in config and config["headers"]:
            sorted_headers = "".join(
                f'<li><strong>{k}:</strong> {v}</li>'
                for k, v in sorted(config["headers"].items())
            )
            headers_html = f"""
            <div class="config">
                <h4>Request Headers</h4>
                <ul class="tag-list">{sorted_headers}</ul>
            </div>
            """
        config_html = env_html + headers_html

    spans_html = ""
    for span in trace:
        all_span_paths = {k for k in span.keys() if k not in ["meta", "metrics"]}
        all_span_paths.update({f"meta.{k}" for k in span.get("meta", {}).keys()})
        all_span_paths.update({f"metrics.{k}" for k in span.get("metrics", {}).keys()})

        missing_tag_paths = failing_paths - all_span_paths
        present_failing_paths = failing_paths.intersection(all_span_paths)
        has_failing_tags = bool(missing_tag_paths or present_failing_paths)
        fail_indicator = "❌" if has_failing_tags else ""

        top_level_tags = {k: v for k, v in span.items() if k not in ["meta", "metrics"]}
        sorted_top_level = "".join(
            f'<li><strong {highlight_if_failing(k)}>{k}:</strong> {v}</li>'
            for k, v in sorted(top_level_tags.items())
        )
        meta_html = "".join(
            f'<li><strong {highlight_if_failing(f"meta.{k}")}>{k}:</strong> {v}</li>'
            for k, v in sorted(span.get("meta", {}).items())
        )
        metrics_html = "".join(
            f'<li><strong {highlight_if_failing(f"metrics.{k}")}>{k}:</strong> {v}</li>'
            for k, v in sorted(span.get("metrics", {}).items())
        )

        missing_tags_html = ""
        if missing_tag_paths:
            missing_items_html = "".join(
                f'<li><strong style="background-color: #ff4d4d;">{path}</strong>: (missing)</li>'
                for path in sorted(missing_tag_paths)
            )
            missing_tags_html = f"""
            <h5 class="span-header">Missing Tags</h5>
            <ul class="tag-list">{missing_items_html}</ul>
            """

        spans_html += f"""
        <div class="span {'span-failing' if has_failing_tags else ''}">
            <h4 class="span-header">Span: {span.get("name", "N/A")} {fail_indicator}</h4>
            <div class="span-details">
                {missing_tags_html}
                <h5 class="span-header">Top-Level Tags</h5>
                <ul class="tag-list">{sorted_top_level}</ul>
                <h5 class="span-header">Meta</h5>
                <ul class="tag-list">{meta_html}</ul>
                <h5 class="span-header">Metrics</h5>
                <ul class="tag-list">{metrics_html}</ul>
            </div>
        </div>
        """
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Trace Details</title>
        <style>
            body {{ font-family: sans-serif; }}
            .span {{ border: 1px solid #ccc; margin: 10px; padding: 10px; border-radius: 5px; }}
            .span-failing {{ border-color: #d44; border-width: 2px; }}
            .span-header {{ margin-top: 0; margin-bottom: 0; }}
            .span-details {{ padding-left: 20px; }}
            .tag-list {{
                font-family: monospace;
                list-style-type: none;
                padding-left: 20px;
                margin-top: 5px;
            }}
            h5 {{ margin-top: 10px; margin-bottom: 5px; }}
        </style>
    </head>
    <body>
        <h1>Trace Details <a href="{datadog_url}" target="_blank">(View in Datadog)</a></h1>
        {config_html}
        {spans_html}
    </body>
    </html>
    """
