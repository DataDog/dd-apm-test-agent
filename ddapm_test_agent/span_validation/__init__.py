from typing import Any
from typing import Dict
import re
from ..checks import Check


class Exists:
    """Marker to assert that a tag or metric exists, regardless of its value."""

    pass


class Matches:
    """Marker to assert that a tag value matches a regex pattern."""

    def __init__(self, pattern: str, flags: int = 0):
        self.pattern = re.compile(pattern, flags)

    def __repr__(self):
        return f"Matches('{self.pattern.pattern}')"


class IsInstanceOf:
    """Marker to assert that a value is an instance of a given type."""

    def __init__(self, type_):
        self.type = type_

    def __repr__(self):
        return f"IsInstanceOf({self.type.__name__})"


class SpanAssertion:
    def __init__(self, span: Dict[str, Any], parent_check: "Check" = None):
        self.span = span
        self.parent_check = parent_check

    def _fail(self, message: str):
        if self.parent_check:
            self.parent_check.fail(message)
        else:
            raise AssertionError(message)

    def _assert_value(self, actual: Any, expected: Any, path: str):
        if isinstance(expected, Exists):
            if actual is None:
                self._fail(f"Expected '{path}' to exist, but it was not found.")
            return

        if actual is None:
            self._fail(f"Expected '{path}' to be {expected}, but it was not found.")
            return

        if isinstance(expected, Matches):
            if not expected.pattern.match(str(actual)):
                self._fail(
                    f"Value for '{path}' ({actual}) does not match pattern {expected.pattern.pattern}."
                )
            return

        if isinstance(expected, IsInstanceOf):
            if not isinstance(actual, expected.type):
                self._fail(
                    f"Value for '{path}' ({actual}) has type {type(actual).__name__}, but expected {expected.type.__name__}."
                )
            return

        if str(actual) != str(expected):
            self._fail(f"Value for '{path}' is {actual}, but expected {expected}.")

    def assert_span_matches(self, expected_span: Dict[str, Any]) -> "SpanAssertion":
        for key, expected_value in expected_span.items():
            path = key
            if key == "meta":
                if not isinstance(expected_value, dict):
                    self._fail("Expected 'meta' to be a dictionary.")
                for meta_key, expected_meta_value in expected_value.items():
                    meta_path = f"meta.{meta_key}"
                    actual_meta_value = self.span.get("meta", {}).get(meta_key)
                    self._assert_value(actual_meta_value, expected_meta_value, meta_path)
            elif key == "metrics":
                if not isinstance(expected_value, dict):
                    self._fail("Expected 'metrics' to be a dictionary.")
                for metric_key, expected_metric_value in expected_value.items():
                    metric_path = f"metrics.{metric_key}"
                    actual_metric_value = self.span.get("metrics", {}).get(metric_key)
                    self._assert_value(
                        actual_metric_value, expected_metric_value, metric_path
                    )
            else:
                actual_value = self.span.get(key)
                self._assert_value(actual_value, expected_value, path)
        return self
