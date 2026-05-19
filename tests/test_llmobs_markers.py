from ddapm_test_agent.markers import MarkerEvaluator
from ddapm_test_agent.markers import apply_eval_metrics


def _span(
    span_id,
    name,
    kind,
    start_ns,
    *,
    input_value="",
    output_value="",
    status="ok",
    parent_id="root",
    turn_id=1,
    metrics=None,
):
    return {
        "name": name,
        "span_id": span_id,
        "trace_id": "trace-marker",
        "parent_id": parent_id,
        "session_id": "session-marker",
        "status": status,
        "duration": 1_000_000,
        "start_ns": start_ns,
        "ml_app": "test-app",
        "service": "test-service",
        "env": "test",
        "meta": {
            "span": {"kind": kind},
            "input": {"value": input_value},
            "output": {"value": output_value},
            "metadata": {"turn_id": turn_id},
        },
        "metrics": metrics or {},
        "tags": ["session_id:session-marker"],
    }


def _metric_by_label(metrics, label):
    return [metric for metric in metrics if metric["label"] == label]


def test_marker_evaluator_detects_builtin_points_ranges_and_measures():
    spans = [
        _span(
            "root",
            "agent",
            "agent",
            1_000_000_000,
            input_value="Why do you keep doing the wrong thing?",
            parent_id="undefined",
            turn_id=1,
        ),
        _span(
            "failed-test",
            "Bash",
            "tool",
            2_000_000_000,
            input_value='{"command": "pytest tests"}',
            output_value="FAILED tests/test_example.py",
            status="error",
            turn_id=1,
        ),
        _span(
            "edit",
            "Edit",
            "tool",
            3_000_000_000,
            input_value='{"file_path": "tests/test_example.py"}',
            turn_id=2,
        ),
        _span(
            "passed-test",
            "Bash",
            "tool",
            4_000_000_000,
            input_value='{"command": "pytest tests"}',
            output_value="1 passed",
            turn_id=3,
        ),
        _span(
            "commit",
            "Bash",
            "tool",
            5_000_000_000,
            input_value='{"command": "git commit -m \'fix tests\'"}',
            output_value="[main abc123] fix tests",
            turn_id=4,
        ),
        _span(
            "denied",
            "Bash",
            "tool",
            6_000_000_000,
            input_value='{"command": "cat /private/file"}',
            output_value="permission denied",
            status="error",
            turn_id=5,
        ),
    ]

    output = MarkerEvaluator().evaluate(spans)
    labels = {metric["label"] for metric in output.eval_metrics}

    assert "user-frustration" in labels
    assert "git-commit" in labels
    assert "test-failed" in labels
    assert "test-passed" in labels
    assert "permission-denied" in labels
    assert "test-fix-cycle" in labels
    assert _metric_by_label(output.eval_metrics, "frustration-count")[0]["score_value"] == 1.0
    assert _metric_by_label(output.eval_metrics, "commit-count")[0]["score_value"] == 1.0
    assert _metric_by_label(output.eval_metrics, "test-fix-cycle-count")[0]["score_value"] == 1.0
    assert _metric_by_label(output.eval_metrics, "test-pass-rate")[0]["score_value"] == 0.5

    task_names = {span["name"] for span in output.synthetic_spans if span["meta"]["span"]["kind"] == "task"}
    assert "test-fix-cycle" in task_names
    assert "metric.test-pass-rate" in task_names

    apply_eval_metrics(spans, output.eval_metrics)
    assert spans[0]["evaluations"]["custom"]["user-frustration"] == "warn"
    assert spans[1]["evaluations"]["custom"]["test-fix-cycle"]["outcome"] == "success"
    assert spans[0]["evaluations"]["custom"]["test-pass-rate"] == 0.5


def test_marker_evaluator_supports_yaml_any_of_bracket_and_cost(tmp_path):
    config_path = tmp_path / "markers.yaml"
    config_path.write_text(
        """
version: 1
points:
  - name: costly-or-denied
    severity: warn
    match:
      any_of:
        - turn_cost_above: 1.5
        - denied: true
ranges:
  - name: edit-window
    bracket:
      starts_when:
        tool: Edit
      ends_when:
        tool: Bash
    on_complete: success
measures:
  - name: costly-count
    count:
      point: costly-or-denied
""",
        encoding="utf-8",
    )
    spans = [
        _span(
            "root",
            "agent",
            "agent",
            1_000_000_000,
            parent_id="undefined",
            metrics={"estimated_total_cost": 2.0},
        ),
        _span("edit", "Edit", "tool", 2_000_000_000),
        _span("bash", "Bash", "tool", 3_000_000_000),
    ]

    output = MarkerEvaluator(str(config_path)).evaluate(spans)
    labels = {metric["label"] for metric in output.eval_metrics}

    assert "costly-or-denied" in labels
    assert "edit-window" in labels
    assert _metric_by_label(output.eval_metrics, "costly-count")[0]["score_value"] == 1.0
