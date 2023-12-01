from aiohttp import FormData


async def test_tracerflare(agent):
    expected_output = {
        "source": "tracer_test",
        "case_id": "12345",
        "email": "its.me@datadoghq.com",
        "hostname": "my.hostname",
        "flare_file": "UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==",
    }
    form = FormData()
    form.add_field("source", "tracer_test")
    form.add_field("case_id", "12345")
    form.add_field("email", "its.me@datadoghq.com")
    form.add_field("hostname", "my.hostname")
    form.add_field(
        "flare_file",
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        filename="test-flare.zip",
        content_type="application/octet-stream",
    )
    resp = await agent.post("/tracer_flare/v1", data=form)
    assert resp.status == 200
    flares = await agent.get("/test/session/tracerflares")
    assert await flares.json() == [expected_output]


async def test_tracerflare_missing_case_id(agent):
    expected_output = {
        "source": "tracer_test",
        "email": "its.me@datadoghq.com",
        "hostname": "my.hostname",
        "flare_file": "UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==",
    }
    form = FormData()
    form.add_field("source", "tracer_test")
    form.add_field("email", "its.me@datadoghq.com")
    form.add_field("hostname", "my.hostname")
    form.add_field(
        "flare_file",
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        filename="test-flare.zip",
        content_type="application/octet-stream",
    )
    resp = await agent.post("/tracer_flare/v1", data=form)
    assert resp.status == 400
    flares = await agent.get("/test/session/tracerflares")
    assert await flares.json() == [expected_output]


async def test_tracerflare_not_multipart(agent):
    expected_output = {
        "error": "multipart/* content type expected",
    }
    form = {
        "source": "tracer_test",
        "case_id": "12345",
        "email": "its.me@datadoghq.com",
        "hostname": "my.hostname",
    }
    resp = await agent.post("/tracer_flare/v1", data=form)
    assert resp.status == 400
    flares = await agent.get("/test/session/tracerflares")
    assert await flares.json() == [expected_output]
