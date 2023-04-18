from ddapm_test_agent.apmtelemetry import v2_decode


def test_decode_v2(
    v2_reference_http_apmtelemetry_payload_data_raw,
    v2_reference_http_apmtelemetry_payload_data,
):
    # decode_v2 is just json.loads for now
    assert v2_decode(v2_reference_http_apmtelemetry_payload_data) == v2_reference_http_apmtelemetry_payload_data_raw
