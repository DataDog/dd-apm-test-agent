import logging
from pathlib import Path

import pytest


log = logging.getLogger(__name__)


def test_span_validations_results():
    path = Path("./validation_failures.txt")
    with open(path, "r+") as f:
        data = f.readlines()
        lines = set([line.rstrip() for line in data])
        lines.discard("")
        f.truncate(0)

    if len(lines) > 0:
        for error in lines:
            log.error(error)
        pytest.fail(reason=f"{len(lines)} Span Tag Validation Errors Occurred.")
    else:
        log.info("APM-TEST-AGENT-SPAN-VALIDATION ------------------------------> SUCCESS")


if __name__ == "__main__":
    test_span_validations_results()
