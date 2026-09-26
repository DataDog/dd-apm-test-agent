"""Live, locally cached model prices for Lapdog's LLM spans.

The v2 genai-prices feed is a versioned data contract.  Only the text-token
units represented by LLMObs metrics are priced here; no package dependency or
network request is needed while calculating a span's cost.
"""

from datetime import datetime
from datetime import time
from datetime import timedelta
from datetime import timezone
from decimal import Decimal
from decimal import InvalidOperation
from decimal import ROUND_HALF_UP
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
import urllib.error
import urllib.request

from .paths import LAPDOG_DIR


log = logging.getLogger(__name__)

PRICES_URL = "https://raw.githubusercontent.com/pydantic/genai-prices/refs/heads/main/prices/new_data/v2/data_slim.json"
PRICE_FILE = Path(LAPDOG_DIR) / "pydantic-genai-pricing-slim.json"
ETAG_FILE = Path(LAPDOG_DIR) / "pydantic-genai-pricing-slim.etag"
MAX_PRICE_BYTES = 5_000_000

COST_METRIC_KEYS = frozenset(
    {
        "estimated_non_cached_input_cost",
        "estimated_cache_write_input_cost",
        "estimated_cache_read_input_cost",
        "estimated_input_cost",
        "estimated_output_cost",
        "estimated_total_cost",
    }
)


def _validate_match(rule: Any) -> None:
    if not isinstance(rule, dict) or len(rule) != 1:
        raise ValueError("invalid model match rule")
    operator, value = next(iter(rule.items()))
    if operator in ("or", "and") and isinstance(value, list) and value:
        for child in value:
            _validate_match(child)
    elif operator in ("equals", "starts_with", "ends_with", "contains") and isinstance(value, str):
        return
    elif operator == "regex" and isinstance(value, str):
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("invalid model match regex") from exc
    else:
        raise ValueError("unsupported model match rule")


def _utc_time(value: str) -> time:
    return datetime.strptime(value[:-1] if value.endswith("Z") else value, "%H:%M:%S").time()


def _validate_rate(value: Any) -> None:
    if isinstance(value, dict):
        _validate_rate(value.get("base"))
        tiers = value.get("tiers")
        if not isinstance(tiers, list):
            raise ValueError("invalid price tiers")
        for tier in tiers:
            if not isinstance(tier, dict) or type(tier.get("start")) is not int or tier["start"] < 0:
                raise ValueError("invalid price tier")
            _validate_rate(tier.get("price"))
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid price")
    try:
        if not Decimal(str(value)).is_finite() or value < 0:
            raise ValueError("invalid price")
    except InvalidOperation as exc:
        raise ValueError("invalid price") from exc


def parse_price_data(data: bytes) -> List[Dict[str, Any]]:
    """Validate the part of the v2 feed used for text-token pricing."""
    if len(data) > MAX_PRICE_BYTES:
        raise ValueError("pricing feed is too large")
    providers = json.loads(data)
    if not isinstance(providers, list) or not providers:
        raise ValueError("pricing feed must be a nonempty provider list")
    for provider in providers:
        if not isinstance(provider, dict) or not isinstance(provider.get("id"), str):
            raise ValueError("invalid pricing provider")
        models = provider.get("models")
        if not isinstance(models, list):
            raise ValueError("invalid pricing models")
        for key in ("provider_match", "model_match"):
            if provider.get(key) is not None:
                _validate_match(provider[key])
        for model in models:
            if not isinstance(model, dict) or not isinstance(model.get("id"), str):
                raise ValueError("invalid pricing model")
            _validate_match(model.get("match"))
            choices = model.get("prices")
            if isinstance(choices, dict):
                choices = [{"prices": choices}]
            if not isinstance(choices, list) or not choices:
                raise ValueError("invalid model prices")
            for choice in choices:
                prices = choice.get("prices") if isinstance(choice, dict) else None
                if not isinstance(prices, dict):
                    raise ValueError("invalid price choice")
                constraint = choice.get("constraint")
                if constraint is not None:
                    if not isinstance(constraint, dict) or set(constraint) - {"start_date", "start_time", "end_time"}:
                        raise ValueError("unsupported price constraint")
                    for key, value in constraint.items():
                        if not isinstance(value, str):
                            raise ValueError("invalid price constraint")
                        if key == "start_date":
                            datetime.fromisoformat(value)
                        else:
                            _utc_time(value)
                for key in ("input_mtok", "cache_write_mtok", "cache_read_mtok", "output_mtok"):
                    if key in prices:
                        _validate_rate(prices[key])
    return providers


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(path.parent), prefix=f".{path.name}.", delete=False) as temp:
            temp_path = temp.name
            temp.write(content)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_path, str(path))
    finally:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)


def refresh_price_file() -> bool:
    """Conditionally download prices; return True only if the local data changed."""
    headers = {"User-Agent": "lapdog-model-pricing", "Accept": "application/json"}
    try:
        old_data = PRICE_FILE.read_bytes()
        parse_price_data(old_data)
        valid_cache = True
    except (OSError, ValueError):
        old_data = b""
        valid_cache = False
    if valid_cache:
        try:
            etag = ETAG_FILE.read_text().strip()
            if etag:
                headers["If-None-Match"] = etag
        except OSError:
            pass
    request = urllib.request.Request(PRICES_URL, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status == 304:
                return False
            data = response.read(MAX_PRICE_BYTES + 1)
            parse_price_data(data)
            new_etag = response.headers.get("ETag")
        changed = hashlib.sha256(data).digest() != hashlib.sha256(old_data).digest()
        if changed:
            _atomic_write(PRICE_FILE, data)
        if new_etag:
            _atomic_write(ETAG_FILE, new_etag.encode("utf-8"))
        return changed
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return False
        log.warning("Unable to refresh Lapdog model prices: HTTP %s", exc.code)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        log.warning("Unable to refresh Lapdog model prices: %s", exc)
    return False


def _matches(rule: Dict[str, Any], value: str) -> bool:
    operator, expected = next(iter(rule.items()))
    if operator == "or":
        return any(_matches(child, value) for child in expected)
    if operator == "and":
        return all(_matches(child, value) for child in expected)
    if operator == "regex":
        return re.search(expected, value) is not None
    actual = value.lower()
    target = expected.lower()
    if operator == "equals":
        return actual == target
    if operator == "starts_with":
        return actual.startswith(target)
    if operator == "ends_with":
        return actual.endswith(target)
    return target in actual


def _active_constraint(constraint: Dict[str, str], when: datetime) -> bool:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)
    start_date = constraint.get("start_date")
    if start_date and when.date() < datetime.fromisoformat(start_date).date():
        return False
    start_time = constraint.get("start_time")
    end_time = constraint.get("end_time")
    if start_time and end_time:
        start = _utc_time(start_time)
        end = _utc_time(end_time)
        current = when.time()
        return start <= current < end if start <= end else current >= start or current < end
    if start_time and when.time() < _utc_time(start_time):
        return False
    if end_time and when.time() >= _utc_time(end_time):
        return False
    return True


def _rate(value: Any, total_input_tokens: int) -> Decimal:
    if isinstance(value, dict):
        selected = value["base"]
        for tier in value["tiers"]:
            if total_input_tokens > tier["start"]:
                selected = tier["price"]
        value = selected
    return Decimal(str(value))


def _nano(tokens: int, price_per_million: Decimal) -> int:
    return int((Decimal(tokens) * price_per_million * 1000).to_integral_value(rounding=ROUND_HALF_UP))


def _pricing_time(when: Optional[Union[datetime, int]]) -> datetime:
    """Accept a datetime or a span's Unix nanosecond timestamp."""
    if isinstance(when, datetime):
        return when
    if type(when) is int and when > 0:
        try:
            seconds, nanoseconds = divmod(when, 1_000_000_000)
            return datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(microseconds=nanoseconds // 1000)
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(timezone.utc)


class PricingCatalog:
    def __init__(self, providers: List[Dict[str, Any]]) -> None:
        self.providers = providers
        self._model_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}

    def _provider(self, model_id: str, provider_id: str) -> Optional[Dict[str, Any]]:
        if provider_id:
            for provider in self.providers:
                if provider["id"].lower() == provider_id.lower() or (
                    provider.get("provider_match") and _matches(provider["provider_match"], provider_id)
                ):
                    return provider
        for provider in self.providers:
            if provider.get("model_match") and _matches(provider["model_match"], model_id):
                return provider
        return None

    def _find_model(self, model_id: str, provider_id: str) -> Optional[Dict[str, Any]]:
        key = (model_id.lower(), provider_id.lower())
        if key not in self._model_cache:
            provider = self._provider(model_id, provider_id)
            model = None
            if provider:
                model = next((m for m in provider["models"] if _matches(m["match"], model_id)), None)
                if model is None:
                    for fallback_id in provider.get("fallback_model_providers") or []:
                        fallback = next((p for p in self.providers if p["id"] == fallback_id), None)
                        if fallback:
                            model = next((m for m in fallback["models"] if _matches(m["match"], model_id)), None)
                            if model:
                                break
            self._model_cache[key] = model
        return self._model_cache[key]

    def calculate(
        self,
        model_id: str,
        provider_id: str,
        non_cached_input_tokens: int,
        cache_write_tokens: int,
        cache_read_tokens: int,
        output_tokens: int,
        when: Optional[Union[datetime, int]] = None,
    ) -> Optional[Dict[str, int]]:
        if not model_id or any(
            type(n) is not int or n < 0
            for n in (non_cached_input_tokens, cache_write_tokens, cache_read_tokens, output_tokens)
        ):
            return None
        if "/" in model_id:
            prefix, remainder = model_id.split("/", 1)
            if prefix and remainder and (not provider_id or prefix.lower() == provider_id.lower()):
                if self._provider(remainder, prefix) is not None:
                    provider_id, model_id = prefix, remainder
        model = self._find_model(model_id, provider_id)
        if model is None:
            return None
        choices = model["prices"]
        if isinstance(choices, dict):
            prices = choices
        else:
            price_time = _pricing_time(when)
            prices = next(
                (
                    choice["prices"]
                    for choice in reversed(choices)
                    if not choice.get("constraint") or _active_constraint(choice["constraint"], price_time)
                ),
                choices[0]["prices"],
            )
        if "input_mtok" not in prices and "output_mtok" not in prices:
            return None
        total_input = non_cached_input_tokens + cache_write_tokens + cache_read_tokens
        input_rate = _rate(prices.get("input_mtok", 0), total_input)
        non_cached = _nano(non_cached_input_tokens, input_rate)
        cache_write = _nano(
            cache_write_tokens, _rate(prices.get("cache_write_mtok", prices.get("input_mtok", 0)), total_input)
        )
        cache_read = _nano(
            cache_read_tokens, _rate(prices.get("cache_read_mtok", prices.get("input_mtok", 0)), total_input)
        )
        output = _nano(output_tokens, _rate(prices.get("output_mtok", 0), total_input))
        input_cost = non_cached + cache_write + cache_read
        return {
            "estimated_non_cached_input_cost": non_cached,
            "estimated_cache_write_input_cost": cache_write,
            "estimated_cache_read_input_cost": cache_read,
            "estimated_input_cost": input_cost,
            "estimated_output_cost": output,
            "estimated_total_cost": input_cost + output,
        }


_catalog: Optional[PricingCatalog] = None
_catalog_stamp: Optional[Tuple[int, int]] = None


def _current_catalog() -> Optional[PricingCatalog]:
    global _catalog, _catalog_stamp
    try:
        stat = PRICE_FILE.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return _catalog
    if stamp != _catalog_stamp:
        try:
            candidate = PricingCatalog(parse_price_data(PRICE_FILE.read_bytes()))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            log.warning("Unable to load Lapdog model prices: %s", exc)
            return _catalog
        _catalog = candidate
        _catalog_stamp = stamp
    return _catalog


def compute_cost_metrics(
    model_id: str,
    provider_id: str,
    non_cached_input_tokens: int,
    cache_write_tokens: int,
    cache_read_tokens: int,
    output_tokens: int,
    when: Optional[Union[datetime, int]] = None,
) -> Optional[Dict[str, int]]:
    catalog = _current_catalog()
    if catalog is None:
        return None
    return catalog.calculate(
        model_id, provider_id, non_cached_input_tokens, cache_write_tokens, cache_read_tokens, output_tokens, when
    )


def estimate_span_cost(span: Dict[str, Any]) -> bool:
    """Add a local estimate to an unpriced LLMObs span; preserve supplied costs."""
    meta = span.get("meta")
    metrics = span.get("metrics")
    if not isinstance(meta, dict) or not isinstance(metrics, dict):
        return False
    kind = meta.get("span", {}).get("kind") if isinstance(meta.get("span"), dict) else meta.get("span.kind", "llm")
    if kind != "llm" or any(key in metrics for key in COST_METRIC_KEYS):
        return False
    model = meta.get("model_name")
    if not isinstance(model, str) or not model:
        return False
    provider = meta.get("model_provider") or ""
    if not isinstance(provider, str):
        provider = ""
    read = metrics.get("cache_read_input_tokens", metrics.get("cached_input_tokens", 0))
    write = metrics.get("cache_write_input_tokens", 0)
    total_input = metrics.get("input_tokens")
    explicit_non_cached = metrics.get("non_cached_input_tokens")
    output = metrics.get("output_tokens", 0)
    if total_input is None and explicit_non_cached is None:
        return False
    if any(type(value) is not int or value < 0 for value in (read, write, output)):
        return False
    if explicit_non_cached is not None:
        non_cached = explicit_non_cached
    elif type(total_input) is int and total_input >= read + write:
        non_cached = total_input - read - write
    else:
        return False
    if type(non_cached) is not int or non_cached < 0:
        return False
    result = compute_cost_metrics(model, provider, non_cached, write, read, output, span.get("start_ns"))
    if result is None:
        return False
    metrics.update(result)
    return True
