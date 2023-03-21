import json

from ddapm_test_agent.responses import ResponsesMixin


async def test_remoteconfig(
    agent,
):
    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"


async def test_remoteconfig_create_payload(
    agent,
    v07_reference_http_remoteconfig_payload_data,
    v07_reference_http_remoteconfig_payload_data_raw,
):
    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await agent.post(
        "/test/session/responses/config",
        data=v07_reference_http_remoteconfig_payload_data,
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == v07_reference_http_remoteconfig_payload_data_raw


async def test_remoteconfig_create_payload_and_clear(
    agent,
    v07_reference_http_remoteconfig_payload_data,
    v07_reference_http_remoteconfig_payload_data_raw,
):
    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await agent.post(
        "/test/session/responses/config",
        data=v07_reference_http_remoteconfig_payload_data,
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == v07_reference_http_remoteconfig_payload_data_raw

    resp = await agent.post(
        "/test/session/responses/config",
        data="{}",
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"


async def test_remoteconfig_put_payload(
    agent,
):
    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"

    resp = await agent.put(
        "/test/session/responses/config",
        data='{"a":"b"}',
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == {"a": "b"}

    resp = await agent.put(
        "/test/session/responses/config",
        data='{"c":"d"}',
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == {"a": "b", "c": "d"}


async def test_remoteconfig_create_path_payload(
    agent,
):
    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert content == "{}"
    data = {"path": "2/ASM_DATA/1234", "msg": '{"exclusions": {"a":"b"}}'}
    resp = await agent.post(
        "/test/session/responses/config/path",
        data=json.dumps(data),
    )
    assert resp.status == 202, await resp.text()

    resp = await agent.post("/v0.7/config")
    content = await resp.text()
    assert resp.status == 200
    assert json.loads(content) == ResponsesMixin._build_config_path_response(data["path"], data["msg"])
