"""Lightweight trajectory marker support for local LLMObs testing."""

from __future__ import annotations

from dataclasses import dataclass
import datetime
import fnmatch
import hashlib
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import cast

import yaml

log = logging.getLogger(__name__)

DEFAULT_MARKERS_YAML = r"""
version: 1
points:
  - name: user-frustration
    severity: warn
    confidence: high
    match:
      prompt: "stop doing|don't do|never do|I told you|why do you keep|not what I asked|wrong again"
    extract:
      pattern: "(stop doing|don't do|never do|I told you|why do you keep|not what I asked|wrong again)"
  - name: git-commit
    severity: success
    confidence: high
    match:
      tool: [Bash, Shell, run_shell, terminal, exec_command, bash]
      command: '\bgit(?:\s+-[cC]\s+\S+|\s+--\S+=\S+)*\s+commit\b'
      success: true
    extract:
      message: '-m\s+["'']([^"'']+)'
  - name: git-push
    severity: success
    confidence: high
    match:
      tool: [Bash, Shell, run_shell, terminal, exec_command, bash]
      command: '\bgit(?:\s+-[cC]\s+\S+|\s+--\S+=\S+)*\s+push\b'
      success: true
  - name: test-passed
    severity: success
    confidence: high
    match:
      tool: [Bash, Shell, run_shell, terminal, exec_command, bash]
      command: "pytest|npm test|jest|cargo test|go test|make test"
      success: true
      output: 'passed|\bok\b|all tests passed|0 failed|PASS'
  - name: test-failed
    severity: error
    confidence: high
    match:
      tool: [Bash, Shell, run_shell, terminal, exec_command, bash]
      command: "pytest|npm test|jest|cargo test|go test|make test"
      success: false
  - name: tool-error
    severity: warn
    confidence: high
    match:
      success: false
  - name: permission-denied
    severity: warn
    confidence: high
    match:
      denied: true
ranges:
  - name: test-fix-cycle
    sequence:
      - point: test-failed
      - tool: [Edit, Write, apply_patch]
      - point: test-passed
    on_complete: success
    on_session_end: abandoned
measures:
  - name: frustration-count
    count:
      point: user-frustration
  - name: commit-count
    count:
      point: git-commit
  - name: test-fix-cycle-count
    count:
      range: test-fix-cycle
      outcome: success
  - name: test-pass-rate
    ratio:
      numerator:
        point: test-passed
      denominator:
        any_point: [test-passed, test-failed]
"""


@dataclass
class SpanContext:
    span: Dict[str, Any]
    session_id: str
    trace_id: str
    span_id: str
    kind: str
    name: str
    start_ns: int
    duration: int
    turn_id: int
    success: bool
    denied: bool
    tool_name: str
    command: str
    input_text: str
    output_text: str
    files: List[str]


@dataclass
class PointMatch:
    name: str
    severity: str
    confidence: str
    context: SpanContext
    detail: Dict[str, Any]


@dataclass
class RangeMatch:
    name: str
    outcome: str
    start: SpanContext
    end: SpanContext
    detail: Dict[str, Any]


@dataclass
class MeasureMatch:
    name: str
    value: float
    root: SpanContext


@dataclass
class MarkerEvaluation:
    eval_metrics: List[Dict[str, Any]]
    synthetic_spans: List[Dict[str, Any]]


def enabled_from_env() -> bool:
    value = os.environ.get("DD_APM_TEST_AGENT_MARKERS_ENABLED", "1").strip().lower()
    return value not in ("0", "false", "no", "off")


def parse_eval_metric_payload(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("type") != "evaluation_metric":
        return []
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        return []
    metrics = attrs.get("metrics")
    if not isinstance(metrics, list):
        return []
    return [metric for metric in metrics if isinstance(metric, dict)]


def eval_metric_key(metric: Dict[str, Any]) -> Tuple[str, str, str, int]:
    join_on = metric.get("join_on") if isinstance(metric.get("join_on"), dict) else {}
    span: Dict[str, Any] = {}
    span_value = join_on.get("span") if isinstance(join_on, dict) else None
    if isinstance(span_value, dict):
        span = span_value
    timestamp_ms = metric.get("timestamp_ms", 0)
    try:
        timestamp_int = int(timestamp_ms)
    except (TypeError, ValueError):
        timestamp_int = 0
    return (
        str(span.get("trace_id", "")),
        str(span.get("span_id", "")),
        str(metric.get("label", "")),
        timestamp_int,
    )


def apply_eval_metrics(spans: List[Dict[str, Any]], metrics: Iterable[Dict[str, Any]]) -> int:
    by_ref: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for span in spans:
        trace_id = str(span.get("trace_id", ""))
        span_id = str(span.get("span_id", ""))
        if trace_id and span_id:
            by_ref[(trace_id, span_id)] = span

    applied = 0
    for metric in metrics:
        for span in _matching_spans(metric, spans, by_ref):
            _apply_metric_to_span(span, metric)
            applied += 1
    return applied


def parse_enrichment_body(content_type: str, data: bytes) -> Tuple[List[Dict[str, Any]], int]:
    text = data.decode("utf-8") if isinstance(data, bytes) else str(data)
    events: List[Dict[str, Any]] = []
    ignored = 0

    parsed: Any
    if "jsonl" in content_type.lower():
        parsed = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed.append(json.loads(stripped))
            except json.JSONDecodeError:
                ignored += 1
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = []
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    parsed.append(json.loads(stripped))
                except json.JSONDecodeError:
                    ignored += 1

    candidates = parsed if isinstance(parsed, list) else [parsed]
    for candidate in candidates:
        if _valid_enrichment_event(candidate):
            events.append(candidate)
        else:
            ignored += 1
    return events, ignored


def build_enrichment_outputs(events: List[Dict[str, Any]], spans: List[Dict[str, Any]]) -> MarkerEvaluation:
    synthetic: List[Dict[str, Any]] = []
    evals: List[Dict[str, Any]] = []
    contexts = _build_contexts(spans)
    by_session = _group_contexts_by_session(contexts)

    for event in events:
        session_id = str(event.get("session_id", ""))
        session_contexts = by_session.get(session_id, [])
        root = _root_context(session_contexts)
        if root is None:
            continue
        enrichment_type = str(event.get("enrichment_type", ""))
        if enrichment_type == "milestone":
            span = _span_from_milestone_event(event, root, session_contexts)
            synthetic.append(span)
            eval_metric = _eval_from_milestone_event(event, root, session_contexts)
            if eval_metric:
                evals.append(eval_metric)
        elif enrichment_type == "metric":
            span = _span_from_metric_event(event, root)
            synthetic.append(span)
            evals.append(_score_eval(str(event.get("metric_name", "")), _numeric_value(event.get("value")), root))

    return MarkerEvaluation(eval_metrics=evals, synthetic_spans=synthetic)


class MarkerEvaluator:
    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config = self._load_config(config_path)

    def evaluate(self, spans: List[Dict[str, Any]]) -> MarkerEvaluation:
        base_spans = [span for span in spans if "trajectory.marker.synthetic:true" not in span.get("tags", [])]
        contexts = _build_contexts(base_spans)
        by_session = _group_contexts_by_session(contexts)
        evals: List[Dict[str, Any]] = []
        synthetic: List[Dict[str, Any]] = []

        for session_id, session_contexts in by_session.items():
            points = self._evaluate_points(session_contexts)
            ranges = self._evaluate_ranges(session_contexts, points)
            root = _root_context(session_contexts)
            if root is None:
                continue

            for point in points:
                evals.append(_point_eval(point))
                synthetic.append(_point_span(point))
            for range_match in ranges:
                evals.append(_range_eval(range_match))
                synthetic.append(_range_span(range_match, root))
            for measure in self._evaluate_measures(root, points, ranges):
                evals.append(_score_eval(measure.name, measure.value, measure.root))
                synthetic.append(_metric_span(measure.name, measure.value, measure.root, source="marker-evaluator"))

        return MarkerEvaluation(eval_metrics=evals, synthetic_spans=synthetic)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        path = config_path or os.environ.get("DD_APM_TEST_AGENT_MARKERS_PATH", "")
        if path:
            try:
                with open(path, "r") as f:
                    loaded = yaml.safe_load(f) or {}
                if isinstance(loaded, dict):
                    return loaded
            except Exception as e:
                log.warning("failed to load marker config %s: %s", path, e)
        loaded_default = yaml.safe_load(DEFAULT_MARKERS_YAML) or {}
        return loaded_default if isinstance(loaded_default, dict) else {}

    def _evaluate_points(self, contexts: List[SpanContext]) -> List[PointMatch]:
        points: List[PointMatch] = []
        definitions = self.config.get("points", [])
        if not isinstance(definitions, list):
            return points
        seen: Set[Tuple[str, str]] = set()
        for definition in definitions:
            if not isinstance(definition, dict) or definition.get("disabled"):
                continue
            name = str(definition.get("name", ""))
            if not name:
                continue
            match = definition.get("match", {})
            if not isinstance(match, dict):
                continue
            for context in contexts:
                if _condition_matches(match, context):
                    key = (name, context.span_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    detail = _extract_detail(definition, context)
                    points.append(
                        PointMatch(
                            name=name,
                            severity=str(definition.get("severity", "info")),
                            confidence=str(definition.get("confidence", "medium")),
                            context=context,
                            detail=detail,
                        )
                    )
        return points

    def _evaluate_ranges(self, contexts: List[SpanContext], points: List[PointMatch]) -> List[RangeMatch]:
        ranges: List[RangeMatch] = []
        definitions = self.config.get("ranges", [])
        if not isinstance(definitions, list):
            return ranges
        for definition in definitions:
            if not isinstance(definition, dict) or definition.get("disabled"):
                continue
            name = str(definition.get("name", ""))
            if not name:
                continue
            if isinstance(definition.get("sequence"), list):
                ranges.extend(_evaluate_sequence_range(name, definition, contexts, points))
            elif isinstance(definition.get("bracket"), dict):
                bracket = definition["bracket"]
                ranges.extend(_evaluate_bracket_range(name, definition, bracket, contexts))
        return ranges

    def _evaluate_measures(
        self, root: SpanContext, points: List[PointMatch], ranges: List[RangeMatch]
    ) -> List[MeasureMatch]:
        measures: List[MeasureMatch] = []
        definitions = self.config.get("measures", [])
        if not isinstance(definitions, list):
            return measures
        for definition in definitions:
            if not isinstance(definition, dict) or definition.get("disabled"):
                continue
            name = str(definition.get("name", ""))
            if not name:
                continue
            count = definition.get("count")
            ratio = definition.get("ratio")
            if isinstance(count, dict):
                value = _count_source(count, points, ranges)
                if value:
                    measures.append(MeasureMatch(name=name, value=float(value), root=root))
            elif isinstance(ratio, dict):
                numerator_value = ratio.get("numerator")
                denominator_value = ratio.get("denominator")
                numerator = cast(Dict[str, Any], numerator_value) if isinstance(numerator_value, dict) else {}
                denominator = cast(Dict[str, Any], denominator_value) if isinstance(denominator_value, dict) else {}
                den = _count_source(denominator, points, ranges)
                if den == 0:
                    continue
                ratio_value = float(_count_source(numerator, points, ranges)) / float(den)
                measures.append(MeasureMatch(name=name, value=ratio_value, root=root))
        return measures


def _matching_spans(
    metric: Dict[str, Any],
    spans: List[Dict[str, Any]],
    by_ref: Dict[Tuple[str, str], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    join_on = metric.get("join_on") if isinstance(metric.get("join_on"), dict) else {}
    span_ref = join_on.get("span") if isinstance(join_on, dict) and isinstance(join_on.get("span"), dict) else None
    if span_ref:
        span = by_ref.get((str(span_ref.get("trace_id", "")), str(span_ref.get("span_id", ""))))
        return [span] if span is not None else []

    tag_ref = join_on.get("tag") if isinstance(join_on, dict) and isinstance(join_on.get("tag"), dict) else None
    if tag_ref:
        key = str(tag_ref.get("key", ""))
        value = str(tag_ref.get("value", ""))
        if not key:
            return []
        return [span for span in spans if _tag_value(span, key) == value]
    return []


def _apply_metric_to_span(span: Dict[str, Any], metric: Dict[str, Any]) -> None:
    label = str(metric.get("label", ""))
    metric_type = str(metric.get("metric_type", ""))
    if not label or not metric_type:
        return
    value = _metric_value(metric)
    evaluation = {
        "eval_metric_type": metric_type,
        "value": value,
        "status": "OK",
    }
    for key in ("assessment", "reasoning", "metadata", "tags", "timestamp_ms", "ml_app"):
        if key in metric and metric[key] not in (None, ""):
            evaluation[key] = metric[key]
    span.setdefault("evaluation", {})[label] = evaluation
    span.setdefault("evaluations", {}).setdefault("custom", {})[label] = value
    assessment = metric.get("assessment")
    if assessment:
        span.setdefault("evaluation_assessments", {}).setdefault("custom", {})[label] = assessment


def _metric_value(metric: Dict[str, Any]) -> Any:
    metric_type = str(metric.get("metric_type", ""))
    if metric_type == "categorical":
        return metric.get("categorical_value")
    if metric_type == "score":
        return metric.get("score_value")
    if metric_type == "boolean":
        return metric.get("boolean_value")
    if metric_type == "json":
        return metric.get("json_value")
    return None


def _valid_enrichment_event(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("event_kind") != "enrichment":
        return False
    if not value.get("session_id") or not value.get("timestamp"):
        return False
    enrichment_type = value.get("enrichment_type")
    if enrichment_type == "milestone":
        return bool(value.get("milestone_type"))
    if enrichment_type == "metric":
        return bool(value.get("metric_name")) and "value" in value
    return False


def _build_contexts(spans: List[Dict[str, Any]]) -> List[SpanContext]:
    by_session: Dict[str, List[Dict[str, Any]]] = {}
    for span in spans:
        session_id = str(span.get("session_id", "") or _tag_value(span, "session_id") or span.get("trace_id", ""))
        if session_id:
            by_session.setdefault(session_id, []).append(span)

    contexts: List[SpanContext] = []
    for session_id, session_spans in by_session.items():
        sorted_spans = sorted(session_spans, key=lambda s: int(s.get("start_ns", 0) or 0))
        turn_by_root: Dict[str, int] = {}
        next_turn = 1
        for span in sorted_spans:
            metadata = _metadata(span)
            explicit_turn = _to_int(metadata.get("turn_id"))
            span_id = str(span.get("span_id", ""))
            if explicit_turn is not None:
                turn_by_root[span_id] = explicit_turn
            elif _is_turn_root(span):
                turn_by_root[span_id] = next_turn
                next_turn += 1

        for span in sorted_spans:
            kind = _span_kind(span)
            metadata = _metadata(span)
            span_id = str(span.get("span_id", ""))
            parent_id = str(span.get("parent_id", ""))
            turn_id = _to_int(metadata.get("turn_id"))
            if turn_id is None:
                turn_id = turn_by_root.get(span_id) or turn_by_root.get(parent_id) or next_turn
            contexts.append(_span_context(span, session_id, kind, turn_id))

    contexts.sort(key=lambda c: (c.session_id, c.start_ns, c.span_id))
    return contexts


def _span_context(span: Dict[str, Any], session_id: str, kind: str, turn_id: int) -> SpanContext:
    input_text = _span_text(span, "input")
    output_text = _span_text(span, "output")
    command = _extract_command(input_text)
    tool_name = _tool_name(span, kind)
    return SpanContext(
        span=span,
        session_id=session_id,
        trace_id=str(span.get("trace_id", "")),
        span_id=str(span.get("span_id", "")),
        kind=kind,
        name=str(span.get("name", "")),
        start_ns=int(span.get("start_ns", 0) or 0),
        duration=int(span.get("duration", 0) or 0),
        turn_id=turn_id,
        success=_span_success(span),
        denied=_span_denied(span),
        tool_name=tool_name,
        command=command,
        input_text=input_text,
        output_text=output_text,
        files=_extract_files(input_text),
    )


def _span_kind(span: Dict[str, Any]) -> str:
    meta = span.get("meta", {})
    if isinstance(meta, dict):
        span_meta = meta.get("span")
        if isinstance(span_meta, dict) and span_meta.get("kind"):
            return str(span_meta["kind"])
        if meta.get("span.kind"):
            return str(meta["span.kind"])
    return str(span.get("_ui_kind", ""))


def _is_turn_root(span: Dict[str, Any]) -> bool:
    tags = span.get("tags", [])
    return "trajectory.semantic_type:turn" in tags or (
        _span_kind(span) == "agent" and str(span.get("parent_id", "undefined")) in ("", "undefined", "0")
    )


def _metadata(span: Dict[str, Any]) -> Dict[str, Any]:
    meta = span.get("meta", {})
    if isinstance(meta, dict):
        metadata = meta.get("metadata", {})
        if isinstance(metadata, dict):
            return metadata
    return {}


def _span_text(span: Dict[str, Any], key: str) -> str:
    meta = span.get("meta", {})
    if not isinstance(meta, dict):
        return ""
    value = meta.get(key, {})
    if not isinstance(value, dict):
        return _stringify(value)
    if "value" in value:
        return _stringify(value.get("value"))
    messages = value.get("messages")
    if isinstance(messages, list):
        return "\n".join(_message_text(message) for message in messages if isinstance(message, dict))
    return _stringify(value)


def _message_text(message: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("content", "text"):
        if key in message:
            parts.append(_stringify(message.get(key)))
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        parts.append(_stringify(tool_calls))
    return "\n".join(part for part in parts if part)


def _tool_name(span: Dict[str, Any], kind: str) -> str:
    tag_tool = _tag_value(span, "tool_name")
    if tag_tool:
        return tag_tool
    if kind == "tool":
        return str(span.get("name", ""))
    return ""


def _span_success(span: Dict[str, Any]) -> bool:
    status = str(span.get("status", "ok")).lower()
    if status in ("error", "failed", "fail"):
        return False
    meta = span.get("meta", {})
    if isinstance(meta, dict) and meta.get("error"):
        return False
    return True


def _span_denied(span: Dict[str, Any]) -> bool:
    metadata = _metadata(span)
    if str(metadata.get("permission_denied", "")).lower() == "true":
        return True
    text = (_span_text(span, "output") + "\n" + _stringify(span.get("meta", {}).get("error", ""))).lower()
    return "permission denied" in text or "denied" in text


def _extract_command(text: str) -> str:
    parsed = _parse_jsonish(text)
    if isinstance(parsed, dict):
        for key in ("command", "input", "cmd"):
            value = parsed.get(key)
            if isinstance(value, str):
                return value
    return text


def _extract_files(text: str) -> List[str]:
    parsed = _parse_jsonish(text)
    values: List[str] = []
    if isinstance(parsed, dict):
        for key in ("path", "file", "file_path", "filepath"):
            value = parsed.get(key)
            if isinstance(value, str):
                values.append(value)
        files = parsed.get("files")
        if isinstance(files, list):
            values.extend(str(item) for item in files)
    values.extend(re.findall(r"[\w./-]+\.(?:py|go|ts|tsx|js|jsx|json|yaml|yml|md|toml|rs|java|rb)", text))
    return sorted(set(values))


def _condition_matches(condition: Dict[str, Any], context: SpanContext) -> bool:
    any_of = condition.get("any_of")
    if isinstance(any_of, list):
        return any(isinstance(item, dict) and _condition_matches(item, context) for item in any_of)

    for key, expected in condition.items():
        if key == "any_of":
            continue
        if key == "tool" and not _value_in(expected, context.tool_name):
            return False
        if key == "command" and not _regex_search(expected, context.command):
            return False
        if key == "output" and not _regex_search(expected, context.output_text):
            return False
        if key == "prompt" and not _regex_search(expected, context.input_text):
            return False
        if key == "response" and not _regex_search(expected, context.output_text):
            return False
        if key == "success" and bool(expected) != context.success:
            return False
        if key == "denied" and bool(expected) != context.denied:
            return False
        if key == "file" and not any(_path_matches(str(expected), path) for path in context.files):
            return False
        if key == "turn_cost_above" and not _turn_cost_above(context, expected):
            return False
    return True


def _value_in(expected: Any, actual: str) -> bool:
    if not actual:
        return False
    actual_lower = actual.lower()
    if isinstance(expected, list):
        return any(str(item).lower() == actual_lower for item in expected)
    return str(expected).lower() == actual_lower


def _regex_search(pattern: Any, value: str) -> bool:
    try:
        return re.search(str(pattern), value or "", re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        log.debug("invalid marker regex ignored: %r", pattern)
        return False


def _path_matches(pattern: str, path: str) -> bool:
    for part in pattern.split("|"):
        if fnmatch.fnmatch(path, part) or _regex_search(part, path):
            return True
    return False


def _turn_cost_above(context: SpanContext, expected: Any) -> bool:
    threshold = _to_float(expected)
    if threshold is None:
        return False
    metrics = context.span.get("metrics", {})
    candidates = []
    if isinstance(metrics, dict):
        candidates.extend([metrics.get("estimated_total_cost"), metrics.get("estimated_cost_usd")])
    metadata = _metadata(context.span)
    candidates.extend([metadata.get("estimated_total_cost"), metadata.get("estimated_cost_usd")])
    return any(value is not None and value > threshold for value in (_to_float(c) for c in candidates))


def _extract_detail(definition: Dict[str, Any], context: SpanContext) -> Dict[str, Any]:
    detail = {
        "severity": str(definition.get("severity", "info")),
        "confidence": str(definition.get("confidence", "medium")),
        "source": "marker-evaluator",
    }
    extract = definition.get("extract")
    if isinstance(extract, dict):
        corpus = "\n".join([context.input_text, context.output_text, context.command])
        for key, pattern in extract.items():
            try:
                match = re.search(str(pattern), corpus, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            if match:
                detail[str(key)] = match.group(1) if match.groups() else match.group(0)
    if context.command:
        detail["command"] = context.command
    if context.tool_name:
        detail["tool"] = context.tool_name
    return detail


def _evaluate_sequence_range(
    name: str,
    definition: Dict[str, Any],
    contexts: List[SpanContext],
    points: List[PointMatch],
) -> List[RangeMatch]:
    steps = definition.get("sequence", [])
    if not isinstance(steps, list) or not steps:
        return []
    ranges: List[RangeMatch] = []
    ordered = sorted(contexts, key=lambda c: (c.start_ns, c.span_id))
    point_by_context: Dict[Tuple[str, str], List[PointMatch]] = {}
    for point in points:
        point_by_context.setdefault((point.context.span_id, point.name), []).append(point)

    index = 0
    start_context: Optional[SpanContext] = None
    for context in ordered:
        step = steps[index]
        if not isinstance(step, dict):
            continue
        if _range_step_matches(step, context, point_by_context):
            if index == 0:
                start_context = context
            index += 1
            if index == len(steps) and start_context is not None:
                ranges.append(
                    RangeMatch(
                        name=name,
                        outcome=str(definition.get("on_complete", "success")),
                        start=start_context,
                        end=context,
                        detail={"source": "marker-evaluator"},
                    )
                )
                index = 0
                start_context = None
    if index > 0 and start_context is not None and definition.get("on_session_end"):
        ranges.append(
            RangeMatch(
                name=name,
                outcome=str(definition.get("on_session_end")),
                start=start_context,
                end=ordered[-1],
                detail={"source": "marker-evaluator", "incomplete": True},
            )
        )
    return ranges


def _evaluate_bracket_range(
    name: str,
    definition: Dict[str, Any],
    bracket: Dict[str, Any],
    contexts: List[SpanContext],
) -> List[RangeMatch]:
    starts_when = bracket.get("starts_when")
    ends_when = bracket.get("ends_when")
    if not isinstance(starts_when, dict) or not isinstance(ends_when, dict):
        return []
    ranges: List[RangeMatch] = []
    active: Optional[SpanContext] = None
    for context in sorted(contexts, key=lambda c: (c.start_ns, c.span_id)):
        if active is None and _condition_matches(starts_when, context):
            active = context
            continue
        if active is not None and _condition_matches(ends_when, context):
            ranges.append(
                RangeMatch(
                    name=name,
                    outcome=str(definition.get("on_complete", "success")),
                    start=active,
                    end=context,
                    detail={"source": "marker-evaluator"},
                )
            )
            active = None
    if active is not None and definition.get("on_session_end") and contexts:
        ranges.append(
            RangeMatch(
                name=name,
                outcome=str(definition.get("on_session_end")),
                start=active,
                end=contexts[-1],
                detail={"source": "marker-evaluator", "incomplete": True},
            )
        )
    return ranges


def _range_step_matches(
    step: Dict[str, Any],
    context: SpanContext,
    point_by_context: Dict[Tuple[str, str], List[PointMatch]],
) -> bool:
    point = step.get("point")
    if point:
        return bool(point_by_context.get((context.span_id, str(point))))
    return _condition_matches(step, context)


def _count_source(source: Dict[str, Any], points: List[PointMatch], ranges: List[RangeMatch]) -> int:
    if "point" in source:
        return sum(1 for point in points if point.name == source["point"])
    if "any_point" in source and isinstance(source["any_point"], list):
        names = {str(name) for name in source["any_point"]}
        return sum(1 for point in points if point.name in names)
    if "range" in source:
        outcome = source.get("outcome")
        return sum(
            1
            for range_match in ranges
            if range_match.name == source["range"] and (not outcome or range_match.outcome == outcome)
        )
    return 0


def _point_eval(point: PointMatch) -> Dict[str, Any]:
    value = point.severity
    return {
        "join_on": {"span": {"trace_id": point.context.trace_id, "span_id": point.context.span_id}},
        "label": point.name,
        "metric_type": "categorical",
        "categorical_value": value,
        "assessment": _severity_assessment(point.severity),
        "reasoning": json.dumps(point.detail, sort_keys=True),
        "metadata": point.detail,
        "ml_app": str(point.context.span.get("ml_app", "")),
        "timestamp_ms": _now_ms(),
        "tags": ["source:trajectory", f"confidence:{point.confidence}"],
    }


def _range_eval(range_match: RangeMatch) -> Dict[str, Any]:
    return {
        "join_on": {"span": {"trace_id": range_match.start.trace_id, "span_id": range_match.start.span_id}},
        "label": range_match.name,
        "metric_type": "json",
        "json_value": {
            "turn_start": range_match.start.turn_id,
            "turn_end": range_match.end.turn_id,
            "outcome": range_match.outcome,
            "detail": range_match.detail,
        },
        "assessment": _outcome_assessment(range_match.outcome),
        "ml_app": str(range_match.start.span.get("ml_app", "")),
        "timestamp_ms": _now_ms(),
        "tags": ["source:trajectory"],
    }


def _score_eval(label: str, value: float, root: SpanContext) -> Dict[str, Any]:
    return {
        "join_on": {"span": {"trace_id": root.trace_id, "span_id": root.span_id}},
        "label": label,
        "metric_type": "score",
        "score_value": value,
        "ml_app": str(root.span.get("ml_app", "")),
        "timestamp_ms": _now_ms(),
        "tags": ["source:trajectory"],
    }


def _point_span(point: PointMatch) -> Dict[str, Any]:
    detail = dict(point.detail)
    detail.setdefault("turn_id", point.context.turn_id)
    return _task_span(
        session_id=point.context.session_id,
        name=point.name,
        start_ns=point.context.start_ns,
        duration=0,
        ml_app=str(point.context.span.get("ml_app", "")),
        service=str(point.context.span.get("service", "")),
        env=str(point.context.span.get("env", "")),
        span_key=f"milestone-{point.name}-{point.context.span_id}",
        input_value=point.name,
        output_value=json.dumps(detail, sort_keys=True),
        metadata={"milestone_type": point.name, "turn_id": point.context.turn_id, "severity": point.severity},
        link_span=point.context,
        semantic_type="milestone",
    )


def _range_span(range_match: RangeMatch, root: SpanContext) -> Dict[str, Any]:
    metadata = {
        "milestone_type": range_match.name,
        "turn_start": range_match.start.turn_id,
        "turn_end": range_match.end.turn_id,
        "outcome": range_match.outcome,
    }
    metadata.update(range_match.detail)
    end_ns = range_match.end.start_ns + max(range_match.end.duration, 0)
    duration = max(0, end_ns - range_match.start.start_ns)
    return _task_span(
        session_id=range_match.start.session_id,
        name=range_match.name,
        start_ns=range_match.start.start_ns,
        duration=duration,
        ml_app=str(root.span.get("ml_app", "")),
        service=str(root.span.get("service", "")),
        env=str(root.span.get("env", "")),
        span_key=f"milestone-{range_match.name}-{range_match.start.turn_id}-{range_match.end.turn_id}",
        input_value=range_match.name,
        output_value=json.dumps(metadata, sort_keys=True),
        metadata=metadata,
        link_span=root,
        semantic_type="milestone",
    )


def _metric_span(name: str, value: float, root: SpanContext, source: str) -> Dict[str, Any]:
    return _task_span(
        session_id=root.session_id,
        name=f"metric.{name}",
        start_ns=root.start_ns + max(root.duration, 0),
        duration=0,
        ml_app=str(root.span.get("ml_app", "")),
        service=str(root.span.get("service", "")),
        env=str(root.span.get("env", "")),
        span_key=f"metric-{name}",
        input_value=name,
        output_value=str(value),
        metadata={"metric_name": name, "metric_value": value, "source": source},
        link_span=root,
        semantic_type="metric",
    )


def _span_from_milestone_event(event: Dict[str, Any], root: SpanContext, contexts: List[SpanContext]) -> Dict[str, Any]:
    name = str(event.get("milestone_type", ""))
    turn_start = _to_int(event.get("turn_start"))
    turn_end = _to_int(event.get("turn_end"))
    anchor = _context_for_turn(contexts, turn_start or _to_int(event.get("turn_id"))) or root
    end = _context_for_turn(contexts, turn_end) or anchor
    start_ns = anchor.start_ns if anchor else _timestamp_ns(str(event.get("timestamp", "")))
    duration = 0
    if turn_start is not None and turn_end is not None:
        duration = max(0, end.start_ns + max(end.duration, 0) - start_ns)
    metadata: Dict[str, Any] = {"milestone_type": name}
    for key in ("turn_id", "turn_start", "turn_end"):
        if key in event:
            metadata[key] = event[key]
    detail_value = event.get("detail")
    detail = cast(Dict[str, Any], detail_value) if isinstance(detail_value, dict) else {}
    metadata.update(detail)
    return _task_span(
        session_id=str(event.get("session_id", "")),
        name=name,
        start_ns=start_ns,
        duration=duration,
        ml_app=str(root.span.get("ml_app", "")),
        service=str(root.span.get("service", "")),
        env=str(root.span.get("env", "")),
        span_key=f"enrichment-milestone-{name}-{event.get('timestamp', '')}",
        input_value=name,
        output_value=json.dumps(detail, sort_keys=True) if detail else "",
        metadata=metadata,
        link_span=anchor,
        semantic_type="milestone",
    )


def _span_from_metric_event(event: Dict[str, Any], root: SpanContext) -> Dict[str, Any]:
    return _metric_span(
        str(event.get("metric_name", "")), _numeric_value(event.get("value")), root, source="enrichment"
    )


def _eval_from_milestone_event(
    event: Dict[str, Any], root: SpanContext, contexts: List[SpanContext]
) -> Optional[Dict[str, Any]]:
    name = str(event.get("milestone_type", ""))
    anchor = _context_for_turn(contexts, _to_int(event.get("turn_start")) or _to_int(event.get("turn_id"))) or root
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    if event.get("turn_start") is not None and event.get("turn_end") is not None:
        turn_start = int(event.get("turn_start", anchor.turn_id))
        turn_end = int(event.get("turn_end", anchor.turn_id))
        return {
            "join_on": {"span": {"trace_id": anchor.trace_id, "span_id": anchor.span_id}},
            "label": name,
            "metric_type": "json",
            "json_value": {"turn_start": turn_start, "turn_end": turn_end, "detail": detail},
            "ml_app": str(root.span.get("ml_app", "")),
            "timestamp_ms": _now_ms(),
            "tags": ["source:trajectory"],
        }
    return {
        "join_on": {"span": {"trace_id": anchor.trace_id, "span_id": anchor.span_id}},
        "label": name,
        "metric_type": "categorical",
        "categorical_value": "info",
        "reasoning": json.dumps(detail, sort_keys=True),
        "metadata": detail,
        "ml_app": str(root.span.get("ml_app", "")),
        "timestamp_ms": _now_ms(),
        "tags": ["source:trajectory"],
    }


def _task_span(
    *,
    session_id: str,
    name: str,
    start_ns: int,
    duration: int,
    ml_app: str,
    service: str,
    env: str,
    span_key: str,
    input_value: str,
    output_value: str,
    metadata: Dict[str, Any],
    link_span: SpanContext,
    semantic_type: str,
) -> Dict[str, Any]:
    trace_id = deterministic_trace_id(session_id + ".enrichment")
    span_id = deterministic_span_id(session_id, span_key)
    tags = [
        f"ml_app:{ml_app or 'lapdog'}",
        f"session_id:{session_id}",
        f"service:{service or ml_app or 'lapdog'}",
        f"env:{env or 'local'}",
        f"trajectory.semantic_type:{semantic_type}",
        "trajectory.marker.synthetic:true",
        "source:trajectory-markers",
    ]
    return {
        "span_id": span_id,
        "trace_id": trace_id,
        "parent_id": "undefined",
        "name": name,
        "status": "ok",
        "duration": duration,
        "start_ns": start_ns or _now_ns(),
        "ml_app": ml_app or "lapdog",
        "service": service or ml_app or "lapdog",
        "env": env or "local",
        "session_id": session_id,
        "tags": tags,
        "meta": {
            "span": {"kind": "task"},
            "input": {"value": input_value},
            "output": {"value": output_value},
            "metadata": metadata,
        },
        "metrics": {},
        "span_links": [
            {
                "span_id": link_span.span_id,
                "trace_id": link_span.trace_id,
                "attributes": {"trajectory.link.type": "enrichment"},
            }
        ],
    }


def deterministic_trace_id(value: str) -> str:
    return _big_endian_uint64_decimal(hashlib.sha256(value.encode("utf-8")).digest()[:8])


def deterministic_span_id(session_id: str, span_key: str) -> str:
    return _big_endian_uint64_decimal(hashlib.sha256(f"{session_id}::{span_key}".encode("utf-8")).digest()[:8])


def _big_endian_uint64_decimal(data: bytes) -> str:
    value = int.from_bytes(data, byteorder="big", signed=False)
    return str(value or 1)


def _severity_assessment(severity: str) -> str:
    if severity == "error":
        return "fail"
    if severity == "success":
        return "pass"
    if severity == "warn":
        return "needs_review"
    return ""


def _outcome_assessment(outcome: str) -> str:
    if outcome == "success":
        return "pass"
    if outcome == "abandoned":
        return "fail"
    return ""


def _group_contexts_by_session(contexts: List[SpanContext]) -> Dict[str, List[SpanContext]]:
    result: Dict[str, List[SpanContext]] = {}
    for context in contexts:
        result.setdefault(context.session_id, []).append(context)
    return result


def _root_context(contexts: List[SpanContext]) -> Optional[SpanContext]:
    roots = [
        context for context in contexts if str(context.span.get("parent_id", "undefined")) in ("", "undefined", "0")
    ]
    if roots:
        return sorted(roots, key=lambda c: (c.start_ns, c.span_id))[0]
    return contexts[0] if contexts else None


def _context_for_turn(contexts: List[SpanContext], turn_id: Optional[int]) -> Optional[SpanContext]:
    if turn_id is None:
        return None
    matches = [context for context in contexts if context.turn_id == turn_id]
    if not matches:
        return None
    roots = [context for context in matches if context.kind in ("agent", "step")]
    return sorted(roots or matches, key=lambda c: (c.start_ns, c.span_id))[0]


def _numeric_value(value: Any) -> float:
    coerced = _to_float(value)
    return 0.0 if coerced is None else coerced


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _tag_value(span: Dict[str, Any], key: str) -> Optional[str]:
    prefix = f"{key}:"
    for tag in span.get("tags", []):
        if isinstance(tag, str) and tag.startswith(prefix):
            return tag.split(":", 1)[1]
    return None


def _parse_jsonish(text: str) -> Any:
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def _timestamp_ns(timestamp: str) -> int:
    if not timestamp:
        return _now_ns()
    try:
        parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return int(parsed.timestamp() * 1_000_000_000)
    except ValueError:
        return _now_ns()


def _now_ns() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)


def _now_ms() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000)
