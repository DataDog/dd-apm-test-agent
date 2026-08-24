from ddapm_test_agent.codex_cost_tracker import compute_openai_cost_metrics


class TestModelLookup:
    def test_gpt_5_6(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.6", 1000, 0, 0) != {}

    def test_gpt_5_6_terra(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.6-terra", 1000, 0, 0) != {}

    def test_gpt_5_3_codex(self) -> None:
        assert compute_openai_cost_metrics("gpt-5.3-codex", 1000, 0, 0) != {}

    def test_unknown_model_returns_empty(self) -> None:
        assert compute_openai_cost_metrics("claude-opus-4-8", 1000, 0, 0) == {}


class TestCostCalculation:
    def test_gpt_5_6_sol_pricing(self) -> None:
        # gpt-5.6 (Sol): $5 input / $0.50 cached / $30 output per Mtok.
        result = compute_openai_cost_metrics("gpt-5.6", 100, 20, 50)
        assert result["estimated_non_cached_input_cost"] == 100 * 5_000
        assert result["estimated_cache_read_input_cost"] == 20 * 500
        assert result["estimated_output_cost"] == 50 * 30_000
        assert result["estimated_input_cost"] == 100 * 5_000 + 20 * 500
        assert result["estimated_total_cost"] == 100 * 5_000 + 20 * 500 + 50 * 30_000

    def test_gpt_5_6_terra_not_shadowed_by_sol(self) -> None:
        # "gpt-5.6-terra" must match the Terra tier, not the "gpt-5.6" catch-all.
        result = compute_openai_cost_metrics("gpt-5.6-terra", 100, 0, 0)
        assert result["estimated_non_cached_input_cost"] == 100 * 2_000

    def test_gpt_5_3_codex_pricing(self) -> None:
        # gpt-5.3-codex: $1.75 input / $0.175 cached / $14 output per Mtok.
        result = compute_openai_cost_metrics("gpt-5.3-codex", 100, 20, 50)
        assert result["estimated_non_cached_input_cost"] == 100 * 1_750
        assert result["estimated_cache_read_input_cost"] == 20 * 175
        assert result["estimated_output_cost"] == 50 * 14_000
