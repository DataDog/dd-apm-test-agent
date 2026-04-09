"""Cost tracking for Anthropic models used with Claude Code.

Pricing is in nanodollars per token (1 nanodollar = 1e-9 USD), matching the
convention used in dd-go/domains/ml-observability/libs/costtracker/model_prices.go
and the metric keys expected by the web-ui LLM observability span detail view:

    estimated_total_cost
    estimated_input_cost
    estimated_output_cost
    estimated_non_cached_input_cost
    estimated_cache_write_input_cost
    estimated_cache_read_input_cost

Pricing data last updated 2025-10 based on Anthropic public pricing and
dd-go/domains/ml-observability/libs/costtracker/model_prices.go.
Only the popular models used with Claude Code are included.
"""

from dataclasses import dataclass
from typing import Dict
from typing import FrozenSet
from typing import List
from typing import Optional
from typing import Tuple


@dataclass(frozen=True)
class _PriceTier:
    """Per-token costs in nanodollars for one pricing tier."""

    # Token volume bounds (inclusive).  max_input_tokens=0 means unbounded.
    min_input_tokens: int
    max_input_tokens: int
    cost_per_non_cached_input: int
    cost_per_cache_write: int
    cost_per_cache_read: int
    cost_per_output: int


# ---------------------------------------------------------------------------
# Pricing table
# Keys are canonical model-name prefixes (without date suffix, lowercase,
# hyphens only).  Model IDs returned by the Anthropic API, such as
# "claude-opus-4-6-20250514", are matched by iterating these prefixes in
# order from most- to least-specific.
#
# Pricing source: dd-go costtracker model_prices.go (updated 2025-10-21) and
# Anthropic public pricing pages.  All costs are nanodollars / token.
# ---------------------------------------------------------------------------

# Keys added by the local cost tracker that must be stripped before forwarding
# spans to the Datadog backend.  The backend processor computes its own costs;
# sending our local estimates would duplicate or conflict with those values.
COST_METRIC_KEYS: FrozenSet[str] = frozenset(
    {
        "estimated_non_cached_input_cost",
        "estimated_cache_write_input_cost",
        "estimated_cache_read_input_cost",
        "estimated_input_cost",
        "estimated_output_cost",
        "estimated_total_cost",
    }
)

_ONE_TIER = 0  # sentinel: no upper bound on a single tier

_PRICING: List[Tuple[str, List[_PriceTier]]] = [
    # ---- Opus ---------------------------------------------------------------
    # claude-opus-4-6 / claude-opus-4.6  (latest)
    (
        "claude-opus-4-6",
        [_PriceTier(0, _ONE_TIER, 15_000, 18_750, 1_500, 75_000)],
    ),
    # claude-opus-4 / claude-opus-4.5  (same unit prices as 4-6)
    (
        "claude-opus-4",
        [_PriceTier(0, _ONE_TIER, 15_000, 18_750, 1_500, 75_000)],
    ),
    # claude-3-opus
    (
        "claude-3-opus",
        [_PriceTier(0, _ONE_TIER, 15_000, 18_750, 1_500, 75_000)],
    ),
    # ---- Sonnet -------------------------------------------------------------
    # claude-sonnet-4-6 / claude-sonnet-4.6  (latest)
    (
        "claude-sonnet-4-6",
        [_PriceTier(0, _ONE_TIER, 3_000, 3_750, 300, 15_000)],
    ),
    # claude-sonnet-4-5 / claude-sonnet-4.5  (tiered at 200k tokens)
    (
        "claude-sonnet-4-5",
        [
            _PriceTier(0, 200_000, 3_000, 3_750, 300, 15_000),
            _PriceTier(200_001, _ONE_TIER, 6_000, 7_500, 600, 22_500),
        ],
    ),
    # claude-sonnet-4  (no date suffix variant)
    (
        "claude-sonnet-4",
        [_PriceTier(0, _ONE_TIER, 3_000, 3_750, 300, 15_000)],
    ),
    # claude-3-7-sonnet / claude-3.7-sonnet
    (
        "claude-3-7-sonnet",
        [_PriceTier(0, _ONE_TIER, 3_000, 3_750, 300, 15_000)],
    ),
    # claude-3-5-sonnet / claude-3.5-sonnet
    (
        "claude-3-5-sonnet",
        [_PriceTier(0, _ONE_TIER, 3_000, 3_750, 300, 15_000)],
    ),
    # ---- Haiku --------------------------------------------------------------
    # claude-haiku-4-5 / claude-haiku-4.5  (latest)
    (
        "claude-haiku-4-5",
        [_PriceTier(0, _ONE_TIER, 1_000, 1_250, 100, 5_000)],
    ),
    # claude-3-5-haiku / claude-3.5-haiku
    (
        "claude-3-5-haiku",
        [_PriceTier(0, _ONE_TIER, 800, 1_000, 80, 4_000)],
    ),
    # claude-3-haiku
    (
        "claude-3-haiku",
        [_PriceTier(0, _ONE_TIER, 250, 300, 30, 1_250)],
    ),
]

# Pre-built lookup: prefix -> tiers (most-specific prefix first is guaranteed
# by the ordering of _PRICING above, so a simple linear scan is correct).
_PREFIX_TO_TIERS: Dict[str, List[_PriceTier]] = {prefix: tiers for prefix, tiers in _PRICING}
_PREFIXES: List[str] = [prefix for prefix, _ in _PRICING]


def _resolve_tier(tiers: List[_PriceTier], total_input_tokens: int) -> Optional[_PriceTier]:
    for tier in tiers:
        if total_input_tokens < tier.min_input_tokens:
            continue
        if tier.max_input_tokens == _ONE_TIER or total_input_tokens <= tier.max_input_tokens:
            return tier
    # Fall back to last tier (handles edge cases)
    return tiers[-1] if tiers else None


def _find_tiers(model_id: str) -> Optional[List[_PriceTier]]:
    """Return pricing tiers for a model ID, matching by prefix."""
    normalized = model_id.lower()
    for prefix in _PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "-"):
            return _PREFIX_TO_TIERS[prefix]
    return None


def compute_cost_metrics(
    model_id: str,
    non_cached_input_tokens: int,
    cache_write_tokens: int,
    cache_read_tokens: int,
    output_tokens: int,
) -> Optional[Dict[str, int]]:
    """Compute estimated cost metrics for a single LLM span.

    Args:
        model_id: Anthropic model ID as returned by the API (e.g. "claude-opus-4-6-20250514").
        non_cached_input_tokens: Fresh (non-cached) input tokens.
        cache_write_tokens: Tokens written to the prompt cache.
        cache_read_tokens: Tokens read from the prompt cache.
        output_tokens: Output tokens generated.

    Returns:
        Dict of estimated cost metrics in nanodollars, or None if the model
        is not in the pricing table.
    """
    tiers = _find_tiers(model_id)
    if tiers is None:
        return None

    total_input_tokens = non_cached_input_tokens + cache_write_tokens + cache_read_tokens
    tier = _resolve_tier(tiers, total_input_tokens)
    if tier is None:
        return None

    non_cached_input_cost = non_cached_input_tokens * tier.cost_per_non_cached_input
    cache_write_cost = cache_write_tokens * tier.cost_per_cache_write
    cache_read_cost = cache_read_tokens * tier.cost_per_cache_read
    output_cost = output_tokens * tier.cost_per_output

    input_cost = non_cached_input_cost + cache_write_cost + cache_read_cost
    total_cost = input_cost + output_cost

    return {
        "estimated_non_cached_input_cost": non_cached_input_cost,
        "estimated_cache_write_input_cost": cache_write_cost,
        "estimated_cache_read_input_cost": cache_read_cost,
        "estimated_input_cost": input_cost,
        "estimated_output_cost": output_cost,
        "estimated_total_cost": total_cost,
    }
