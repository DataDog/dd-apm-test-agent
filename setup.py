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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="BSD 3",
    packages=find_packages(exclude=["tests*"]),
    package_data={"ddapm_test_agent": ["py.typed"]},
    python_requires=">=3.8",
    install_requires=[
        "aiohttp",
        "ddsketch",
        "msgpack",
        "requests",
        "typing_extensions",
        "yarl",
        "jsonschema",
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
