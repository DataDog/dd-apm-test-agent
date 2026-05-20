"""Cost tracking for OpenAI models used by Codex.

Pricing is in nanodollars per token (1 nanodollar = 1e-9 USD), matching the
metric keys expected by the web-ui LLM observability span detail view.

Pricing data last updated 2026-05 from OpenAI API pricing pages. GPT-5.5
standard rates are documented for context lengths under 270K tokens.
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


_PRICING: List[_OpenAIPrice] = [
    _OpenAIPrice("gpt-5.5", input_price=5_000, cached_input=500, output=30_000),
    _OpenAIPrice("gpt-5.4-mini", input_price=750, cached_input=75, output=4_500),
    _OpenAIPrice("gpt-5.4", input_price=2_500, cached_input=250, output=15_000),
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

    non_cached_input_cost = non_cached_input_tokens * price.input_price
    cache_read_cost = cached_input_tokens * price.cached_input
    output_cost = output_tokens * price.output
    input_cost = non_cached_input_cost + cache_read_cost

    return {
        "estimated_non_cached_input_cost": non_cached_input_cost,
        "estimated_cache_write_input_cost": 0,
        "estimated_cache_read_input_cost": cache_read_cost,
        "estimated_input_cost": input_cost,
        "estimated_output_cost": output_cost,
        "estimated_total_cost": input_cost + output_cost,
    }
