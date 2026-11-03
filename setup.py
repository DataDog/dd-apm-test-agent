import os
from typing import Any
from typing import List

from setuptools import Extension
from setuptools import find_packages
from setuptools import setup
from setuptools.command.build_ext import build_ext


with open("README.md", "r") as f:
    long_description = f.read()

with open("test_deps.txt") as f:
    testing_deps = [line.strip() for line in f.readlines()]


class OptionalBuildExt(build_ext):
    """Skip the native extension when it cannot be built; the pure-Python install behaves the same."""

    def run(self) -> None:
        try:
            super().run()
        except Exception as e:
            print("WARNING: not building the native trace fast path: %s" % e)

    def build_extension(self, ext: Any) -> None:
        try:
            super().build_extension(ext)
        except Exception as e:
            print("WARNING: not building %s: %s" % (ext.name, e))


ext_modules: List[Any] = []
# DDAPM_TEST_AGENT_PURE_PYTHON=1 builds a pure-Python (py3-none-any) wheel.
if os.environ.get("DDAPM_TEST_AGENT_PURE_PYTHON", "").lower() not in ("1", "true", "yes"):
    try:
        from Cython.Build import cythonize
    except ImportError:
        if os.path.exists("ddapm_test_agent/_native.c"):  # generated C shipped in the sdist
            ext_modules = [Extension("ddapm_test_agent._native", ["ddapm_test_agent/_native.c"])]
        else:
            print("WARNING: Cython is not installed, not building the native trace fast path")
    else:
        try:
            ext_modules = cythonize(
                [Extension("ddapm_test_agent._native", ["ddapm_test_agent/_native.pyx"])],
                compiler_directives={"language_level": "3"},
            )
        except Exception as e:
            print("WARNING: not building the native trace fast path: %s" % e)

setup(
    name="ddapm-test-agent",
    description="Test agent for Datadog APM client libraries",
    url="https://github.com/Datadog/dd-apm-test-agent",
    author="Kyle Verhoog",
    author_email="kyle@verhoog.ca",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="BSD 3",
    packages=find_packages(exclude=["tests*", "releasenotes", "scripts"]),
    package_data={
        "ddapm_test_agent": ["py.typed", "templates/*", "static/*", "_native.pyi", "_native.pyx",],
        "lapdog": ["py.typed", "claude_intercept.mjs", "pi_lapdog_extension.ts", "bootstrap/*", "lapdog-initialize.mjs"],
    },
    python_requires=">=3.8",
    install_requires=[
        "aiohttp",
        "ddsketch[serialization]",
        "msgpack",
        "requests",
        "typing_extensions",
        "yarl",
        "requests-aws4auth",
        "jinja2>=3.0.0",
        "pyyaml",
        # ddtrace libraries officially support opentelemetry-proto 1.33.1
        # which implements the v1.7.0 spec
        "opentelemetry-proto>1.33.0,<1.37.0",
        "protobuf>=3.19.0",
        "grpcio>=1.66.2,<2.0",
        "pywin32; sys_platform == 'win32'",
        "distlib>=0.4.3; sys_platform == 'win32'",
    ],
    tests_require=testing_deps,
    entry_points={
        "console_scripts": [
            "ddapm-test-agent=ddapm_test_agent.agent:main",
            "ddapm-test-agent-fmt=ddapm_test_agent.fmt:main",
            "ddapm-test-agent-session-start=ddapm_test_agent.cmd:main_session_start",
            "ddapm-test-agent-snapshot=ddapm_test_agent.cmd:main_snapshot",
            "lapdog=lapdog.cli:main",
        ]
    },
    extras_require={
        "testing": testing_deps,
        "ddtrace": ["ddtrace"],  # todo: pin?
    },
    ext_modules=ext_modules,
    cmdclass={"build_ext": OptionalBuildExt},
    # Required for mypy compatibility, see
    # https://mypy.readthedocs.io/en/stable/installed_packages.html#making-pep-561-compatible-packages
    zip_safe=False,
)
