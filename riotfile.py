from riot import Venv
from riot import latest


with open("test_deps.txt") as f:
    testing_deps = [line.strip() for line in f.readlines()]


venv = Venv(
    pys=["3"],
    venvs=[
        Venv(
            name="test",
            command="pytest {cmdargs}",
            pys=["3.11", "3.12", "3.13"],
            pkgs={pkg: latest for pkg in testing_deps},
        ),
        Venv(
            pkgs={
                "black": latest,
                "isort": latest,
                "toml": latest,
            },
            pys=["3.11"],
            venvs=[
                Venv(
                    name="black",
                    command="black {cmdargs}",
                ),
                Venv(
                    name="fmt",
                    command="isort . && black .",
                ),
                Venv(
                    name="check_fmt",
                    command="isort --check . && black --check .",
                ),
            ],
        ),
        Venv(
            name="flake8",
            command="flake8 {cmdargs}",
            pys=["3.11"],
            pkgs={
                "flake8": latest,
                "flake8-blind-except": latest,
                "flake8-builtins": latest,
                "flake8-docstrings": latest,
                # "flake8-logging-format": latest,
                "flake8-rst-docstrings": latest,
                "pygments": latest,
                "toml": latest,
            },
        ),
        Venv(
            name="mypy",
            create=True,
            command="mypy {cmdargs}",
            pys=["3.11"],
            pkgs={
                "mypy": "==1.7.1",
                "pytest": latest,
                "types-protobuf": latest,
                "types-requests": latest,
                "types-setuptools": latest,
                "types-PyYAML": latest,
            },
        ),
        Venv(
            name="reno",
            pkgs={
                "reno": latest,
            },
            command="reno {cmdargs}",
        ),
    ],
)
