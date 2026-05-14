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

Pricing data last updated 2025-11 based on:
  * Anthropic public pricing: https://www.anthropic.com/pricing#api
  * pi-ai models.generated.js (the data Claude Code itself uses to compute
    the self-reported per-turn cost shown in its UI):
    @mariozechner/pi-ai/dist/models.generated.js
  * dd-go/domains/ml-observability/libs/costtracker/model_prices.go

Note: Anthropic significantly reduced Opus prices starting with Opus 4.5
(Nov 2025).  Opus 4.5 / 4.6 / 4.7 cost $5 / $25 / $0.50 / $6.25 per Mtok,
whereas Opus 4 / 4.1 / 3 still cost $15 / $75 / $1.50 / $18.75 per Mtok.
Using the old Opus rates for 4.5+ overcharges by exactly 3x.

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
# Pricing sources (see module docstring):
#   * Anthropic public pricing: https://www.anthropic.com/pricing#api
#   * pi-ai @mariozechner/pi-ai models.generated.js (matches what Claude Code
#     reports as its own per-turn cost)
#   * dd-go costtracker model_prices.go
# All costs are nanodollars / token (1 nanodollar = 1e-9 USD).
# Per-Mtok USD pricing translates directly: $1/Mtok = 1_000 nano/token,
# $5/Mtok = 5_000 nano/token, $15/Mtok = 15_000 nano/token, etc.
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
    # ---- Opus 4.5+ (reduced pricing, Nov 2025) ------------------------------
    # $5 / $25 / $0.50 cache-read / $6.25 cache-write per Mtok.
    # Source: Anthropic pricing page; pi-ai models.generated.js entries
    # "anthropic.claude-opus-4-5-...", "...claude-opus-4-6-v1", "...claude-opus-4-7".
    #
    # claude-opus-4-7 / claude-opus-4.7  (latest)
    (
        "claude-opus-4-7",
        [_PriceTier(0, _ONE_TIER, 5_000, 6_250, 500, 25_000)],
    ),
    # claude-opus-4-6 / claude-opus-4.6
    (
        "claude-opus-4-6",
        [_PriceTier(0, _ONE_TIER, 5_000, 6_250, 500, 25_000)],
    ),
    # claude-opus-4-5 / claude-opus-4.5
    (
        "claude-opus-4-5",
        [_PriceTier(0, _ONE_TIER, 5_000, 6_250, 500, 25_000)],
    ),
    # ---- Opus 4 / 4.1 / 3 (legacy higher pricing) ---------------------------
    # $15 / $75 / $1.50 cache-read / $18.75 cache-write per Mtok.
    #
    # claude-opus-4-1 / claude-opus-4.1  (must come before "claude-opus-4")
    (
        "claude-opus-4-1",
        [_PriceTier(0, _ONE_TIER, 15_000, 18_750, 1_500, 75_000)],
    ),
    # claude-opus-4  (base 4.0)
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


# 1 nanodollar = 1e-9 USD
_NANODOLLARS_PER_DOLLAR = 1_000_000_000


def cost_from_provider_usage(
    cost: Dict[str, float],
) -> Dict[str, int]:
    """Convert provider-reported cost (in USD) to nanodollar cost metrics.

    The *cost* dict is expected to have keys matching the pi extension's format::

        {"input": 0.00015, "output": 0.03, "cacheRead": 0.028, "cacheWrite": 0.001, "total": 0.059}

    Returns a dict with the same metric keys as ``compute_cost_metrics``.
    """
    def _to_nano(v: float) -> int:
        return int(round(v * _NANODOLLARS_PER_DOLLAR))

    non_cached_input = _to_nano(cost.get("input", 0.0))
    cache_write = _to_nano(cost.get("cacheWrite", 0.0))
    cache_read = _to_nano(cost.get("cacheRead", 0.0))
    output = _to_nano(cost.get("output", 0.0))
    input_cost = non_cached_input + cache_write + cache_read
    total = _to_nano(cost.get("total", 0.0))
    # Prefer the provider's total if available; fall back to sum of parts.
    if total == 0 and input_cost + output > 0:
        total = input_cost + output

    return {
        "estimated_non_cached_input_cost": non_cached_input,
        "estimated_cache_write_input_cost": cache_write,
        "estimated_cache_read_input_cost": cache_read,
        "estimated_input_cost": input_cost,
        "estimated_output_cost": output,
        "estimated_total_cost": total,
    }


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
