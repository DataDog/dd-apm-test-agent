import contextlib
import os
import platform
import subprocess
import time
from typing import Dict
from typing import Generator
from typing import List
from typing import Tuple

import pytest


pytestmark = pytest.mark.skipif(os.getenv("SKIP_CONTAINER") is not None, reason="SKIP_CONTAINER set")
pytestmark = pytest.mark.skipif(
    platform.system() == "Darwin" and os.getenv("GITHUB_ACTIONS") is not None,
    reason="Github actions doesn't support docker",
)


class DockerContainer:
    def __init__(self, cid: str):
        self.id = cid

    def logs(self):
        p = subprocess.run(["docker", "logs", self.id], capture_output=True, check=True)
        return p.stdout.decode(), p.stderr.decode()


@contextlib.contextmanager
def docker_run(
    image: str,
    env: Dict[str, str],
    volumes: List[str],
    cmd: List[str] = [],
    ports: List[Tuple[str, str]] = [],
) -> Generator[DockerContainer, None, None]:
    _cmd: List[str] = [
        "docker",
        "run",
        "-i",
        "--rm",
        "--detach",
    ]
    for k, v in env.items():
        _cmd.extend(["-e", "%s=%s" % (k, v)])
    for v in volumes:
        _cmd.extend(["-v", v])
    for k, v in ports:
        _cmd.extend(["-p", "%s:%s" % (k, v)])
    _cmd += [image]
    _cmd.extend(cmd)

    # Run the docker container
    p = subprocess.run(_cmd, capture_output=True)
    assert p.returncode == 0, p.stderr
    cid = p.stdout.decode().strip()
    assert cid
    yield DockerContainer(cid)
    # Kill the container
    subprocess.run(["docker", "kill", cid], capture_output=True, check=True)


@pytest.fixture(scope="session")
def build_image():
    subprocess.run(
        [
            "docker",
            "build",
            "-t",
            "ddapm-test-agent:test",
            "-f",
            "Dockerfile",
            ".",
        ],
        check=True,
    )
    yield
    subprocess.run(
        [
            "docker",
            "rmi",
            "-f",
            "ddapm-test-agent:test",
        ],
        check=True,
    )


@pytest.mark.skipif(platform.system() == "Linux", reason="No socket mounting issues on Linux")
def test_container_uds(build_image, tmp_path_factory):
    uds_dir = tmp_path_factory.mktemp("uds")

    with docker_run(
        image="ddapm-test-agent:test",
        volumes=[f"{str(uds_dir)}:/opt/datadog-agent/run"],
        env={"DD_APM_RECEIVER_SOCKET": "/opt/datadog-agent/run/apm.socket"},
    ) as c:
        for i in range(50):
            stdout, stderr = c.logs()
            if "could not set permissions" in stderr:
                break
            time.sleep(0.1)
        else:
            raise Exception("Test agent did not start in time: %s" % stderr)
