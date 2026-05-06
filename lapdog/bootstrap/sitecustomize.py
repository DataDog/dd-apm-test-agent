"""
Lapdog bootstrap: loaded via PYTHONPATH to instrument Python processes with ddtrace.
Runs as sitecustomize before any user code. Exits cleanly if ddtrace is unavailable.
"""
import os
import sys

try:
    import ddtrace  # noqa: F401
except ImportError:
    # Fall back to lapdog's own ddtrace if one was provided and is ABI-compatible.
    _lapdog_sp = os.environ.get("_LAPDOG_DDTRACE_SITE_PACKAGES")
    if _lapdog_sp:
        sys.path.insert(0, _lapdog_sp)
        try:
            import ddtrace  # noqa: F401
        except ImportError:
            _lapdog_ver = os.environ.get("_LAPDOG_PYTHON_VERSION", "unknown")
            _target_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
            print(
                f"[lapdog] Python version mismatch: lapdog uses Python {_lapdog_ver} "
                f"but this process is Python {_target_ver}.\n"
                "[lapdog] Install ddtrace in your app's Python environment:\n"
                "[lapdog]   pip install ddtrace",
                file=sys.stderr,
            )
            os._exit(1)
    else:
        print(
            "[lapdog] ddtrace is not installed.\n"
            "[lapdog] Install it in your app's Python environment:\n"
            "[lapdog]   pip install ddtrace",
            file=sys.stderr,
        )
        os._exit(1)

import ddtrace.auto  # noqa: F401
