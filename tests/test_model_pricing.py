"""Live pricing contract, local cache, and LLMObs metric conversion."""

from datetime import datetime
from datetime import timezone
import io
import json
from urllib.error import HTTPError

from lapdog import model_pricing


def _feed():
    return [
        {
            "id": "openai",
            "model_match": {"starts_with": "gpt-"},
            "models": [
                {
                    "id": "gpt-test",
                    "match": {"or": [{"equals": "gpt-test"}, {"regex": "^gpt-test-[0-9]{8}$"}]},
                    "prices": {
                        "input_mtok": {"base": 2, "tiers": [{"start": 99, "price": 4}]},
                        "cache_read_mtok": 0.2,
                        "output_mtok": {"base": 10, "tiers": [{"start": 99, "price": 15}]},
                    },
                },
                {
                    "id": "gpt-6-astra",
                    "match": {"equals": "gpt-6-astra"},
                    "prices": {"input_mtok": 7, "output_mtok": 14},
                },
            ],
        },
        {
            "id": "anthropic",
            "model_match": {"contains": "claude"},
            "models": [
                {
                    "id": "claude-sonnet-5",
                    "match": {"equals": "claude-sonnet-5"},
                    "prices": [
                        {"prices": {"input_mtok": 3, "cache_write_mtok": 3.75, "output_mtok": 15}},
                        {
                            "constraint": {"start_date": "2026-09-01"},
                            "prices": {"input_mtok": 2, "cache_write_mtok": 2.5, "output_mtok": 10},
                        },
                    ],
                },
            ],
        },
    ]


def _install_feed(monkeypatch, tmp_path):
    path = tmp_path / "prices.json"
    path.write_bytes(json.dumps(_feed()).encode())
    monkeypatch.setattr(model_pricing, "PRICE_FILE", path)
    monkeypatch.setattr(model_pricing, "ETAG_FILE", tmp_path / "prices.etag")
    monkeypatch.setattr(model_pricing, "_catalog", None)
    monkeypatch.setattr(model_pricing, "_catalog_stamp", None)
    return path


def test_cached_prices_reload_without_restart(monkeypatch, tmp_path):
    path = _install_feed(monkeypatch, tmp_path)
    assert (
        model_pricing.compute_cost_metrics("gpt-6-astra", "openai", 2, 0, 0, 3)["estimated_total_cost"]
        == 2 * 7000 + 3 * 14000
    )
    providers = _feed()
    providers[0]["models"][1]["prices"]["input_mtok"] = 8
    path.write_bytes(json.dumps(providers).encode())
    assert model_pricing.compute_cost_metrics("gpt-6-astra", "openai", 2, 0, 0, 0)["estimated_total_cost"] == 16000


def test_aliases_cache_partitions_and_cliff_tiers(monkeypatch, tmp_path):
    _install_feed(monkeypatch, tmp_path)
    below = model_pricing.compute_cost_metrics("gpt-test-20260926", "openai", 80, 0, 19, 2)
    at = model_pricing.compute_cost_metrics("gpt-test", "openai", 80, 0, 20, 2)
    assert below["estimated_non_cached_input_cost"] == 80 * 2000
    assert below["estimated_cache_read_input_cost"] == 19 * 200
    assert below["estimated_output_cost"] == 2 * 10000
    assert at["estimated_non_cached_input_cost"] == 80 * 4000
    assert at["estimated_output_cost"] == 2 * 15000


def test_dated_prices_and_missing_cache_rate(monkeypatch, tmp_path):
    _install_feed(monkeypatch, tmp_path)
    old = datetime(2026, 8, 31, tzinfo=timezone.utc)
    new = datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert (
        model_pricing.compute_cost_metrics("claude-sonnet-5", "anthropic", 1, 1, 1, 1, old)["estimated_total_cost"]
        == 3000 + 3750 + 3000 + 15000
    )
    assert (
        model_pricing.compute_cost_metrics("claude-sonnet-5", "anthropic", 1, 1, 1, 1, new)["estimated_total_cost"]
        == 2000 + 2500 + 2000 + 10000
    )
    assert (
        model_pricing.compute_cost_metrics("claude-sonnet-5", "anthropic", 1, 1, 1, 1)["estimated_total_cost"]
        == 2000 + 2500 + 2000 + 10000
    )
    old_ns = int(old.timestamp() * 1_000_000_000)
    assert (
        model_pricing.compute_cost_metrics("claude-sonnet-5", "anthropic", 1, 1, 1, 1, old_ns)["estimated_total_cost"]
        == 3000 + 3750 + 3000 + 15000
    )


def test_unmatched_model_or_missing_file_has_no_estimate(monkeypatch, tmp_path):
    _install_feed(monkeypatch, tmp_path)
    assert model_pricing.compute_cost_metrics("unknown", "anthropic", 1, 0, 0, 0) is None
    monkeypatch.setattr(model_pricing, "_catalog", None)
    monkeypatch.setattr(model_pricing, "_catalog_stamp", None)
    monkeypatch.setattr(model_pricing, "PRICE_FILE", tmp_path / "missing.json")
    assert model_pricing.compute_cost_metrics("claude-sonnet-5", "anthropic", 1, 0, 0, 0) is None


def test_generic_span_preserves_existing_cost_and_skips_non_llm(monkeypatch, tmp_path):
    _install_feed(monkeypatch, tmp_path)
    span = {
        "meta": {"span": {"kind": "llm"}, "model_name": "gpt-test", "model_provider": "openai"},
        "metrics": {"input_tokens": 10, "cache_read_input_tokens": 2, "output_tokens": 1},
    }
    assert model_pricing.estimate_span_cost(span)
    assert span["metrics"]["estimated_non_cached_input_cost"] == 8 * 2000
    assert span["metrics"]["estimated_cache_read_input_cost"] == 2 * 200
    assert not model_pricing.estimate_span_cost(span)
    span["meta"]["span"]["kind"] = "tool"
    span["metrics"].pop("estimated_total_cost")
    assert not model_pricing.estimate_span_cost(span)


class _Response(io.BytesIO):
    status = 200

    def __init__(self, body, etag):
        super().__init__(body)
        self.headers = {"ETag": etag}


def test_refresh_uses_etag_and_does_not_rewrite_unchanged_data(monkeypatch, tmp_path):
    path = tmp_path / "prices.json"
    etag = tmp_path / "prices.etag"
    monkeypatch.setattr(model_pricing, "PRICE_FILE", path)
    monkeypatch.setattr(model_pricing, "ETAG_FILE", etag)
    body = json.dumps(_feed()).encode()
    requests = []

    def fetch(request, timeout):
        requests.append(request)
        if len(requests) == 2:
            raise HTTPError(request.full_url, 304, "Not Modified", {}, None)
        return _Response(body, '"revision-1"')

    monkeypatch.setattr(model_pricing.urllib.request, "urlopen", fetch)
    assert model_pricing.refresh_price_file()
    assert path.read_bytes() == body
    stamp = path.stat().st_mtime_ns
    assert not model_pricing.refresh_price_file()
    assert requests[1].get_header("If-none-match") == '"revision-1"'
    assert not model_pricing.refresh_price_file()
    assert path.stat().st_mtime_ns == stamp


def test_invalid_refresh_keeps_last_valid_file(monkeypatch, tmp_path):
    path = _install_feed(monkeypatch, tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(
        model_pricing.urllib.request, "urlopen", lambda request, timeout: _Response(b"not json", '"bad"')
    )
    assert not model_pricing.refresh_price_file()
    assert path.read_bytes() == before


def test_corrupt_cache_does_not_send_etag(monkeypatch, tmp_path):
    path = _install_feed(monkeypatch, tmp_path)
    path.write_bytes(b"broken")
    model_pricing.ETAG_FILE.write_text('"stale"')
    requests = []

    def fetch(request, timeout):
        requests.append(request)
        return _Response(json.dumps(_feed()).encode(), '"new"')

    monkeypatch.setattr(model_pricing.urllib.request, "urlopen", fetch)
    assert model_pricing.refresh_price_file()
    assert requests[0].get_header("If-none-match") is None
    assert model_pricing.parse_price_data(path.read_bytes())
