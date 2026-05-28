from ddapm_test_agent.claude_cost_tracker import compute_cost_metrics


class TestModelLookup:
    """Model ID resolution, including date-stamped API IDs and unknown models."""

    def test_exact_match(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6", 1000, 0, 0, 0)
        assert result is not None

    def test_date_stamped_id_opus(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6-20250514", 1000, 0, 0, 0)
        assert result is not None

    def test_date_stamped_id_sonnet(self) -> None:
        result = compute_cost_metrics("claude-sonnet-4-6-20250514", 1000, 0, 0, 0)
        assert result is not None

    def test_date_stamped_id_haiku(self) -> None:
        result = compute_cost_metrics("claude-haiku-4-5-20251001", 1000, 0, 0, 0)
        assert result is not None

    def test_unknown_model_returns_none(self) -> None:
        assert compute_cost_metrics("gpt-4o", 1000, 0, 0, 0) is None

    def test_empty_model_returns_none(self) -> None:
        assert compute_cost_metrics("", 0, 0, 0, 0) is None

    def test_unknown_anthropic_model_returns_none(self) -> None:
        assert compute_cost_metrics("claude-unknown-99", 0, 0, 0, 0) is None


class TestCostCalculation:
    """Correctness of the nanodollar arithmetic for each cost type."""

    # Opus 4.5+ (4-5 / 4-6 / 4-7): input=5000, cache_write=6250, cache_read=500, output=25000
    # Opus 4 / 4.1 / 3: input=15000, cache_write=18750, cache_read=1500, output=75000

    def test_non_cached_input_cost(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6", non_cached_input_tokens=100, cache_write_tokens=0, cache_read_tokens=0, output_tokens=0)
        assert result is not None
        assert result["estimated_non_cached_input_cost"] == 100 * 5_000
        assert result["estimated_cache_write_input_cost"] == 0
        assert result["estimated_cache_read_input_cost"] == 0
        assert result["estimated_output_cost"] == 0
        assert result["estimated_input_cost"] == 100 * 5_000
        assert result["estimated_total_cost"] == 100 * 5_000

    def test_cache_write_cost(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6", non_cached_input_tokens=0, cache_write_tokens=200, cache_read_tokens=0, output_tokens=0)
        assert result is not None
        assert result["estimated_cache_write_input_cost"] == 200 * 6_250
        assert result["estimated_non_cached_input_cost"] == 0

    def test_cache_read_cost(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6", non_cached_input_tokens=0, cache_write_tokens=0, cache_read_tokens=500, output_tokens=0)
        assert result is not None
        assert result["estimated_cache_read_input_cost"] == 500 * 500

    def test_output_cost(self) -> None:
        result = compute_cost_metrics("claude-opus-4-6", non_cached_input_tokens=0, cache_write_tokens=0, cache_read_tokens=0, output_tokens=50)
        assert result is not None
        assert result["estimated_output_cost"] == 50 * 25_000

    def test_all_token_types_combined(self) -> None:
        result = compute_cost_metrics(
            "claude-opus-4-6",
            non_cached_input_tokens=100,
            cache_write_tokens=200,
            cache_read_tokens=500,
            output_tokens=50,
        )
        assert result is not None
        expected_input = 100 * 5_000 + 200 * 6_250 + 500 * 500
        expected_output = 50 * 25_000
        assert result["estimated_input_cost"] == expected_input
        assert result["estimated_output_cost"] == expected_output
        assert result["estimated_total_cost"] == expected_input + expected_output

    def test_legacy_opus_4_pricing(self) -> None:
        # claude-opus-4 (base 4.0) and claude-opus-4-1 keep the older higher rates.
        for model in ("claude-opus-4", "claude-opus-4-20250514", "claude-opus-4-1", "claude-opus-4-1-20250805"):
            result = compute_cost_metrics(model, 100, 200, 500, 50)
            assert result is not None, model
            assert result["estimated_non_cached_input_cost"] == 100 * 15_000, model
            assert result["estimated_cache_write_input_cost"] == 200 * 18_750, model
            assert result["estimated_cache_read_input_cost"] == 500 * 1_500, model
            assert result["estimated_output_cost"] == 50 * 75_000, model

    def test_opus_share_reduced_pricing(self) -> None:
        # Opus 4.5 / 4.6 / 4.7 / 4.8 all use the post-Nov-2025 reduced rates.
        for model in ("claude-opus-4-5", "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8"):
            result = compute_cost_metrics(model, 100, 200, 500, 50)
            assert result is not None, model
            assert result["estimated_non_cached_input_cost"] == 100 * 5_000, model
            assert result["estimated_cache_write_input_cost"] == 200 * 6_250, model
            assert result["estimated_cache_read_input_cost"] == 500 * 500, model
            assert result["estimated_output_cost"] == 50 * 25_000, model

    def test_zero_tokens_returns_all_zeros(self) -> None:
        result = compute_cost_metrics("claude-sonnet-4-6", 0, 0, 0, 0)
        assert result is not None
        assert all(v == 0 for v in result.values())

    def test_haiku_pricing(self) -> None:
        # claude-haiku-4-5: input=1000, cache_write=1250, cache_read=100, output=5000
        result = compute_cost_metrics("claude-haiku-4-5", 1000, 1000, 1000, 1000)
        assert result is not None
        assert result["estimated_non_cached_input_cost"] == 1000 * 1_000
        assert result["estimated_cache_write_input_cost"] == 1000 * 1_250
        assert result["estimated_cache_read_input_cost"] == 1000 * 100
        assert result["estimated_output_cost"] == 1000 * 5_000

    def test_result_contains_all_expected_keys(self) -> None:
        result = compute_cost_metrics("claude-sonnet-4-6", 100, 0, 0, 10)
        assert result is not None
        assert set(result.keys()) == {
            "estimated_non_cached_input_cost",
            "estimated_cache_write_input_cost",
            "estimated_cache_read_input_cost",
            "estimated_input_cost",
            "estimated_output_cost",
            "estimated_total_cost",
        }


class TestTieredPricing:
    """claude-sonnet-4-5 has two tiers: <=200k tokens uses lower rates."""

    def test_low_volume_tier(self) -> None:
        # 100k total input tokens → tier 1: input=3000, output=15000
        result = compute_cost_metrics("claude-sonnet-4-5", non_cached_input_tokens=100_000, cache_write_tokens=0, cache_read_tokens=0, output_tokens=0)
        assert result is not None
        assert result["estimated_non_cached_input_cost"] == 100_000 * 3_000

    def test_high_volume_tier(self) -> None:
        # 300k total input tokens → tier 2: input=6000, output=22500
        result = compute_cost_metrics("claude-sonnet-4-5", non_cached_input_tokens=300_000, cache_write_tokens=0, cache_read_tokens=0, output_tokens=0)
        assert result is not None
        assert result["estimated_non_cached_input_cost"] == 300_000 * 6_000

    def test_tier_boundary_at_200k(self) -> None:
        at_boundary = compute_cost_metrics("claude-sonnet-4-5", non_cached_input_tokens=200_000, cache_write_tokens=0, cache_read_tokens=0, output_tokens=0)
        over_boundary = compute_cost_metrics("claude-sonnet-4-5", non_cached_input_tokens=200_001, cache_write_tokens=0, cache_read_tokens=0, output_tokens=0)
        assert at_boundary is not None
        assert over_boundary is not None
        # Cost per token doubles at tier boundary
        assert over_boundary["estimated_non_cached_input_cost"] > at_boundary["estimated_non_cached_input_cost"]

    def test_high_volume_output_rate(self) -> None:
        # Tier 2 output rate is 22500 nanodollars/token
        result = compute_cost_metrics("claude-sonnet-4-5", non_cached_input_tokens=300_000, cache_write_tokens=0, cache_read_tokens=0, output_tokens=100)
        assert result is not None
        assert result["estimated_output_cost"] == 100 * 22_500
