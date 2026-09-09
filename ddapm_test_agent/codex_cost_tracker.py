"""Cost tracking for OpenAI models used by Codex.

Pricing is in nanodollars per token (1 nanodollar = 1e-9 USD), matching the
metric keys expected by the web-ui LLM observability span detail view.

Pricing data last updated 2026-09 from OpenAI API pricing pages.

Latest models:
  * gpt-6-astra ($10 / $50 per Mtok, 90% cached-input discount). Prompts over
    272K input tokens cost 2x for input/cache and 1.5x for output.
  * gpt-5.6 family (Sol $4 / $20, Terra $2 / $12 per Mtok, 90% cached-input
    discount). Sol's promotional rates are documented through at least
    2026-11-21. Prompts over 272K input tokens cost 2x for input/cache and 1.5x
    for output. The nano-tier "Luna" variant is deliberately left out so it
    resolves to the higher "gpt-5.6" (Sol) rate via prefix match — a
    conservative upper bound, since its own rate was inconsistent across
    sources.
  * gpt-5.3-codex — the current Codex CLI default ($1.75 / $14 per Mtok),
    superseding gpt-5.2-codex at the same rates.
"""

from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


@dataclass(frozen=True)
class _OpenAIPrice:
    prefix: str
    input_price: int
    cached_input: int
    output: int
    long_context_threshold: int = 0


_PRICING: List[_OpenAIPrice] = [
    _OpenAIPrice(
        "gpt-6-astra",
        input_price=10_000,
        cached_input=1_000,
        output=50_000,
        long_context_threshold=272_000,
    ),
    # gpt-5.6 family (Terra listed before the Sol catch-all so it isn't shadowed).
    _OpenAIPrice(
        "gpt-5.6-terra",
        input_price=2_000,
        cached_input=200,
        output=12_000,
        long_context_threshold=272_000,
    ),
    _OpenAIPrice(
        "gpt-5.6",
        input_price=4_000,
        cached_input=400,
        output=20_000,
        long_context_threshold=272_000,
    ),
    _OpenAIPrice("gpt-5.5", input_price=5_000, cached_input=500, output=30_000),
    _OpenAIPrice("gpt-5.4-mini", input_price=750, cached_input=75, output=4_500),
    _OpenAIPrice("gpt-5.4", input_price=2_500, cached_input=250, output=15_000),
    _OpenAIPrice("gpt-5.3-codex", input_price=1_750, cached_input=175, output=14_000),
    _OpenAIPrice("gpt-5.2-codex", input_price=1_750, cached_input=175, output=14_000),
    _OpenAIPrice("gpt-5.2", input_price=1_750, cached_input=175, output=14_000),
    _OpenAIPrice("gpt-5.1-codex-max", input_price=1_250, cached_input=125, output=10_000),
    _OpenAIPrice("gpt-5.1-codex", input_price=1_250, cached_input=125, output=10_000),
    _OpenAIPrice("gpt-5.1", input_price=1_250, cached_input=125, output=10_000),
    _OpenAIPrice("gpt-5-codex", input_price=1_250, cached_input=125, output=10_000),
    _OpenAIPrice("gpt-5", input_price=1_250, cached_input=125, output=10_000),
    _OpenAIPrice("gpt-4.1-mini", input_price=400, cached_input=100, output=1_600),
    _OpenAIPrice("gpt-4.1-nano", input_price=100, cached_input=25, output=400),
    _OpenAIPrice("gpt-4.1", input_price=2_000, cached_input=500, output=8_000),
    _OpenAIPrice("gpt-4o-mini", input_price=150, cached_input=75, output=600),
    _OpenAIPrice("gpt-4o", input_price=2_500, cached_input=1_250, output=10_000),
]

_PREFIXES: List[Tuple[str, _OpenAIPrice]] = [(p.prefix, p) for p in _PRICING]


def _find_price(model_id: str) -> Optional[_OpenAIPrice]:
    normalized = model_id.lower()
    for prefix, price in _PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "-"):
            return price
    return None


def compute_openai_cost_metrics(
    model_id: str,
    non_cached_input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
) -> Dict[str, int]:
    price = _find_price(model_id)
    if price is None:
        return {}

    total_input_tokens = non_cached_input_tokens + cached_input_tokens
    long_context = price.long_context_threshold and total_input_tokens > price.long_context_threshold
    input_multiplier = 2 if long_context else 1
    output_numerator = 3 if long_context else 2
    non_cached_input_cost = non_cached_input_tokens * price.input_price * input_multiplier
    cache_read_cost = cached_input_tokens * price.cached_input * input_multiplier
    output_cost = output_tokens * price.output * output_numerator // 2
    input_cost = non_cached_input_cost + cache_read_cost

    return {
        "estimated_non_cached_input_cost": non_cached_input_cost,
        "estimated_cache_write_input_cost": 0,
        "estimated_cache_read_input_cost": cache_read_cost,
        "estimated_input_cost": input_cost,
        "estimated_output_cost": output_cost,
        "estimated_total_cost": input_cost + output_cost,
    }
