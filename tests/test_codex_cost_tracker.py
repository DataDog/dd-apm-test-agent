from lapdog.codex_cost_tracker import compute_openai_cost_metrics


class TestModelLookup:
    def test_gpt_6_astra(self) -> None:
        assert compute_openai_cost_metrics("gpt-6-astra", 1000, 0, 0) != {}
        assert compute_openai_cost_metrics("gpt-6-astra-2026-09-03", 1000, 0, 0) != {}

    def test_gpt_5_6(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.6", 1000, 0, 0) != {}

    def test_gpt_5_6_terra(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.6-terra", 1000, 0, 0) != {}

    def test_gpt_5_3_codex(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.3-codex", 1000, 0, 0) != {}

    def test_unknown_model_returns_empty(self) -> None:
        assert compute_openai_cost_metrics("claude-opus-4-8", 1000, 0, 0) == {}


class TestCostCalculation:
    def test_gpt_6_astra_pricing(self) -> None:
        # gpt-6-astra: $10 input / $1 cached / $50 output per Mtok.
        result = compute_openai_cost_metrics("gpt-6-astra", 100, 20, 50)
        assert result["estimated_non_cached_input_cost"] == 100 * 10_000
        assert result["estimated_cache_read_input_cost"] == 20 * 1_000
        assert result["estimated_output_cost"] == 50 * 50_000
        assert result["estimated_input_cost"] == 100 * 10_000 + 20 * 1_000
        assert result["estimated_total_cost"] == 100 * 10_000 + 20 * 1_000 + 50 * 50_000

    def test_gpt_6_astra_long_context_pricing(self) -> None:
        # Above 272K input tokens: input/cache cost 2x and output costs 1.5x.
        result = compute_openai_cost_metrics("gpt-6-astra", 272_000, 1, 50)
        assert result["estimated_non_cached_input_cost"] == 272_000 * 10_000 * 2
        assert result["estimated_cache_read_input_cost"] == 1 * 1_000 * 2
        assert result["estimated_output_cost"] == 50 * 50_000 * 3 // 2

    def test_gpt_6_astra_long_context_boundary(self) -> None:
        result = compute_openai_cost_metrics("gpt-6-astra", 272_000, 0, 1)
        assert result["estimated_non_cached_input_cost"] == 272_000 * 10_000
        assert result["estimated_output_cost"] == 50_000

    def test_gpt_5_6_sol_pricing(self) -> None:
        # gpt-5.6 (Sol): $4 input / $0.40 cached / $20 output per Mtok.
        result = compute_openai_cost_metrics("gpt-5.6", 100, 20, 50)
        assert result["estimated_non_cached_input_cost"] == 100 * 4_000
        assert result["estimated_cache_read_input_cost"] == 20 * 400
        assert result["estimated_output_cost"] == 50 * 20_000
        assert result["estimated_input_cost"] == 100 * 4_000 + 20 * 400
        assert result["estimated_total_cost"] == 100 * 4_000 + 20 * 400 + 50 * 20_000

    def test_gpt_5_6_terra_not_shadowed_by_sol(self) -> None:
        # "gpt-5.6-terra" must match the Terra tier, not the "gpt-5.6" catch-all.
        result = compute_openai_cost_metrics("gpt-5.6-terra", 100, 0, 0)
        assert result["estimated_non_cached_input_cost"] == 100 * 2_000

    def test_gpt_5_6_long_context_pricing(self) -> None:
        # Above 272K input tokens: input/cache cost 2x and output costs 1.5x.
        for model, input_price, cached_input, output_price in (
            ("gpt-5.6", 4_000, 400, 20_000),
            ("gpt-5.6-terra", 2_000, 200, 12_000),
        ):
            result = compute_openai_cost_metrics(model, 272_000, 1, 50)
            assert result["estimated_non_cached_input_cost"] == 272_000 * input_price * 2
            assert result["estimated_cache_read_input_cost"] == cached_input * 2
            assert result["estimated_output_cost"] == 50 * output_price * 3 // 2

    def test_gpt_5_6_long_context_boundary(self) -> None:
        for model, input_price, output_price in (
            ("gpt-5.6", 4_000, 20_000),
            ("gpt-5.6-terra", 2_000, 12_000),
        ):
            result = compute_openai_cost_metrics(model, 272_000, 0, 1)
            assert result["estimated_non_cached_input_cost"] == 272_000 * input_price
            assert result["estimated_output_cost"] == output_price

    def test_gpt_5_3_codex_pricing(self) -> None:
        # gpt-5.3-codex: $1.75 input / $0.175 cached / $14 output per Mtok.
        result = compute_openai_cost_metrics("gpt-5.3-codex", 100, 20, 50)
        assert result["estimated_non_cached_input_cost"] == 100 * 1_750
        assert result["estimated_cache_read_input_cost"] == 20 * 175
        assert result["estimated_output_cost"] == 50 * 14_000
