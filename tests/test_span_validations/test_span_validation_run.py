import logging
from pathlib import Path

import pytest


log = logging.getLogger(__name__)


def test_span_validations_no_failures():
    path = Path("tests/test_span_validations/validation_failures.txt")
    with open(path, "r+") as f:
        data = f.readlines()
        lines = set([line.rstrip() for line in data])
        lines.discard("")
        f.truncate(0)

    if len(lines) > 0:
        for error in lines:
            log.error(error)
        pytest.fail(f"{len(lines)} Span Tag Validation Errors Occurred.")


if __name__ == "__main__":
    test_span_validations_no_failures()
