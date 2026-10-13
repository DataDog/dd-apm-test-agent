from typing import Any
from typing import Dict


def set_hidden_metadata(span: Dict[str, Any], **fields: Any) -> None:
    """Merge fields into ``span.meta.metadata._dd`` without replacing existing values."""
    span["meta"].setdefault("metadata", {}).setdefault("_dd", {}).update(fields)
