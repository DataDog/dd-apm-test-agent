import logging
from pathlib import Path

import pytest


log = logging.getLogger(__name__)


def check_span_validations_results():
    path = Path("./ddapm_test_agent/span_validation/validation_failures.txt")
    with open(path, "r+") as f:
        data = f.readlines()
        lines = set([line.rstrip() for line in data])
        lines.discard("")
        f.truncate(0)

    if len(lines) > 0:
        for error in lines:
            log.error(error)
        pytest.fail(pytrace=False, reason=f"{len(lines)} Span Tag Validation Errors Occurred.")


if __name__ == "__main__":
    check_span_validations_results()
