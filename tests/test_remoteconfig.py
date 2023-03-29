import json

import pytest

from ddapm_test_agent.remoteconfig import RemoteConfigServer


@pytest.fixture
async def rc_agent(agent):
    yield agent
    resp = await agent.post(
        "/test/session/responses/config",
        data="{}",
    )
    assert resp.status == 202, await resp.text()


async def test_remoteconfig(
    rc_agent,
):
    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"


async def test_remoteconfig_create_payload(
    rc_agent,
    v07_reference_http_remoteconfig_payload_data,
    v07_reference_http_remoteconfig_payload_data_raw,
):
    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await rc_agent.post(
        "/test/session/responses/config",
        data=v07_reference_http_remoteconfig_payload_data,
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == v07_reference_http_remoteconfig_payload_data_raw


async def test_remoteconfig_create_payload_and_clear(
    rc_agent,
    v07_reference_http_remoteconfig_payload_data,
    v07_reference_http_remoteconfig_payload_data_raw,
):
    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await rc_agent.post(
        "/test/session/responses/config",
        data=v07_reference_http_remoteconfig_payload_data,
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == v07_reference_http_remoteconfig_payload_data_raw

    resp = await rc_agent.post(
        "/test/session/responses/config",
        data="{}",
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"


async def test_remoteconfig_put_payload(
    rc_agent,
):
    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await rc_agent.put(
        "/test/session/responses/config",
        data='{"a":"b"}',
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == {"a": "b"}

    resp = await rc_agent.put(
        "/test/session/responses/config",
        data='{"c":"d"}',
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == {"a": "b", "c": "d"}


async def test_remoteconfig_create_path_payload(
    rc_agent,
):
    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"
    data = {"path": "2/ASM_DATA/1234", "msg": '{"exclusions": {"a":"b"}}'}
    resp = await rc_agent.post(
        "/test/session/responses/config/path",
        data=json.dumps(data),
    )
    assert resp.status == 202, await resp.text()

    resp = await rc_agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == RemoteConfigServer._build_config_path_response(data["path"], data["msg"])
