import json
import os
from typing import Any
from typing import AsyncGenerator
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional

from aiohttp import FormData
from aiohttp import web
from aiohttp.multipart import MultipartWriter
from aiohttp.test_utils import TestClient
from aiohttp.test_utils import TestServer
import pytest


async def serve_handler(request: web.Request) -> web.Response:
    response_headers = {}

    pass_through_value = request.headers.get("Pass-Through-Header-Value")
    if pass_through_value:
        response_headers["Pass-Through-Header-Value"] = pass_through_value

    return web.Response(status=200, text="OK", headers=response_headers)


class CustomFormData(FormData):
    def __init__(self, *args: Any, boundary: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if boundary:
            self._writer = MultipartWriter("form-data", boundary=boundary)


def get_cassettes_for_provider(provider: str, vcr_cassettes_directory: str) -> List[str]:
    custom_dir = os.path.join(vcr_cassettes_directory, provider)
    return [f for f in os.listdir(custom_dir) if os.path.isfile(os.path.join(custom_dir, f))]


@pytest.fixture
async def dummy_server(aiohttp_server: Callable[[web.Application], Awaitable[TestServer]]) -> TestServer:
    app = web.Application()
    app.router.add_post("/serve", serve_handler)

    server = await aiohttp_server(app)
    return server


@pytest.fixture
def vcr_provider_map(dummy_server: TestServer) -> Generator[str, None, None]:
    host = dummy_server.host
    port = dummy_server.port
    provider_map = f"custom=http://{host}:{port}"
    yield provider_map


@pytest.fixture
def vcr_ignore_headers() -> Generator[str, None, None]:
    yield "foo-bar,user-super-secret-api-key"


@pytest.fixture
async def vcr_test_name(agent: TestClient[Any, Any]) -> AsyncGenerator[None, None]:
    await agent.post("/vcr/test/start", json={"test_name": "test_name_prefix"})
    yield
    await agent.post("/vcr/test/stop")


def get_recorded_request(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r") as file:
        data = json.load(file)
        assert isinstance(data, dict)
        return data


async def test_vcr_proxy_make_cassette(agent: TestClient[Any, Any], vcr_cassettes_directory: str) -> None:
    resp = await agent.post("/vcr/custom/serve", json={"foo": "bar"})

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1

    cassette_file = cassette_files[0]
    assert cassette_file.startswith("custom_serve_post")


async def test_vcr_proxy_uses_existing_cassette(agent: TestClient[Any, Any], vcr_cassettes_directory: str) -> None:
    resp = await agent.post("/vcr/custom/serve", json={"foo": "bar"}, headers={"Pass-Through-Header-Value": "test"})

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1

    resp = await agent.post("/vcr/custom/serve", json={"foo": "bar"}, headers={"Pass-Through-Header-Value": "ignored"})

    assert resp.status == 200
    assert await resp.text() == "OK"
    assert (
        resp.headers.get("Pass-Through-Header-Value") == "test"
    )  # should have used the recorded header from the cassette

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1  # should have used this one existing cassette


async def test_vcr_proxy_creates_different_cassettes_for_different_bodies(
    agent: TestClient[Any, Any], vcr_cassettes_directory: str
) -> None:
    resp = await agent.post("/vcr/custom/serve", json={"foo": "bar"})

    assert resp.status == 200
    assert await resp.text() == "OK"

    resp = await agent.post("/vcr/custom/serve", json={"bux": "qux"})

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 2


async def test_vcr_proxy_uses_test_name_prefix(
    agent: TestClient[Any, Any], vcr_cassettes_directory: str, vcr_test_name: Any
) -> None:
    resp = await agent.post("/vcr/custom/serve", json={"foo": "bar"})

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1
    assert cassette_files[0].startswith("test_name_prefix_custom_serve_post")


async def test_vcr_proxy_with_multipart_form_data(agent: TestClient[Any, Any], vcr_cassettes_directory: str) -> None:
    form = CustomFormData(boundary="form-data-boundary-abc123")
    form.add_field("text_field", "some text value")
    form.add_field("number_field", "42")
    form.add_field("file_field", b"fake file content", filename="test.txt", content_type="text/plain")

    resp = await agent.post("/vcr/custom/serve", data=form)

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1

    # Use a second form with the same content but a different boundary
    form = CustomFormData(boundary="form-data-boundary-xyz789")
    form.add_field("text_field", "some text value")
    form.add_field("number_field", "42")
    form.add_field("file_field", b"fake file content", filename="test.txt", content_type="text/plain")

    resp = await agent.post("/vcr/custom/serve", data=form)

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1


async def test_vcr_proxy_does_not_record_ignored_headers(
    agent: TestClient[Any, Any], vcr_cassettes_directory: str
) -> None:
    resp = await agent.post(
        "/vcr/custom/serve",
        json={"foo": "bar"},
        headers={
            "User-Super-Secret-Api-Key": "secret",
            "Foo-Bar": "foo",
            "Authorization": "test",
            "Please-Record-Header": "test",
        },
    )

    assert resp.status == 200
    assert await resp.text() == "OK"

    cassette_files = get_cassettes_for_provider("custom", vcr_cassettes_directory)
    assert len(cassette_files) == 1

    cassette_file = cassette_files[0]
    recorded_request = get_recorded_request(os.path.join(vcr_cassettes_directory, "custom", cassette_file))

    assert recorded_request["request"]["headers"]["Please-Record-Header"] == "test"
    assert "User-Super-Secret-Api-Key" not in recorded_request["request"]["headers"]
    assert "Foo-Bar" not in recorded_request["request"]["headers"]
    assert "Authorization" not in recorded_request["request"]["headers"]
