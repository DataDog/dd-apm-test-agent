from setuptools import find_packages
from setuptools import setup


with open("README.md", "r") as f:
    long_description = f.read()

with open("test_deps.txt") as f:
    testing_deps = [line.strip() for line in f.readlines()]

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
    package_data={"ddapm_test_agent": ["py.typed", "templates/*", "static/*"]},
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
    ],
    tests_require=testing_deps,
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    entry_points={
        "console_scripts": [
            "ddapm-test-agent=ddapm_test_agent.agent:main",
            "ddapm-test-agent-fmt=ddapm_test_agent.fmt:main",
            "ddapm-test-agent-session-start=ddapm_test_agent.cmd:main_session_start",
            "ddapm-test-agent-snapshot=ddapm_test_agent.cmd:main_snapshot",
        ]
    },
    extras_require={
        "testing": testing_deps,
    },
    # Required for mypy compatibility, see
    # https://mypy.readthedocs.io/en/stable/installed_packages.html#making-pep-561-compatible-packages
    zip_safe=False,
)
