import argparse
import glob
import json
import logging
import os
import sys
from typing import List
from typing import Optional

from . import _get_version
from .trace_snapshot import generate_snapshot


log = logging.getLogger(__name__)


def _resolve_files(files: List[str]) -> List[str]:
    """Return a list of json files resolved from the provided list of directories or files"""
    resolved = []
    for fname in files:
        if os.path.isdir(fname):
            curdir = os.getcwd()
            try:
                os.chdir(fname)
                resolved.extend([os.path.join(fname, f) for f in glob.glob("**/*.json", recursive=True)])
            finally:
                os.chdir(curdir)
        else:
            resolved.append(fname)
    return resolved


def main(args: Optional[List[str]] = None) -> None:
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description="Datadog APM Test Agent Snapshot Formatter",
        prog="ddapm-test-agent-fmt",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        help="Print version info and exit.",
    )
    parser.add_argument(
        "-c",
        "--check",
        action="store_true",
        dest="check",
        help="Do not rewrite files, error if any files would be changed.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Set the log level. DEBUG, INFO, WARNING, ERROR, CRITICAL.",
    )
    parser.add_argument(
        "files",
        metavar="FILE",
        type=str,
        nargs="+",
        help="Specific snapshot files or directories to format.",
    )

    parsed_args = parser.parse_args(args=args)
    logging.basicConfig(level=parsed_args.log_level)

    if parsed_args.version:
        print(_get_version())
        sys.exit(0)

    # Find all json files
    resolved_files = _resolve_files(parsed_args.files)
    log.info("Found %d snapshot files to process", len(resolved_files))

    trace_files = []
    trace_stats_files = []
    for f in resolved_files:
        if f.endswith("_tracestats.json"):
            trace_stats_files.append(f)
        else:
            trace_files.append(f)
    log.info("Found %d trace snapshot files to process", len(trace_files))
    log.info("Found %d trace stats snapshot files to process", len(trace_stats_files))

    has_errors = False
    for fname in trace_files:
        log.debug("Checking snapshot file %r", fname)
        try:
            # Read the original file data
            with open(fname, "r") as fp:
                original = fp.read()

            # Parse and re-format
            traces = json.loads(original)
            formatted = generate_snapshot(traces)

            # Only do anything if something changed
            if formatted != original:
                log.debug("Snapshot file %r has changes", fname)
                if parsed_args.check:
                    # If we are in check mode and we changed the content, error
                    log.error("Snapshot file %r would be reformatted!", fname)
                    has_errors = True
                else:
                    # Rewrite the original file with the new formatted version
                    with open(fname, "w") as fp:
                        fp.write(formatted)
                    log.info("Snapshot file %r was formatted", fname)

        except Exception:
            log.exception("Error processing file %r", fname)
            has_errors = True

    if has_errors:
        sys.exit(-1)


if __name__ == "__main__":
    main()
