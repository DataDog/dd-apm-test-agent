"""LLM Observability Query Parser with Boolean Logic Support.

This module implements a query parser that supports:
- Boolean operators: AND, OR, NOT
- Parentheses grouping
- Attribute filters: @field:value
- Tag filters: field:value
- Range queries: @field:[min TO max]
- Comparison operators: >, <, >=, <=
- Wildcards: * (zero or more chars), ? (exactly one char)
- Existence queries: _exists_:field, _missing_:field
- IN operator: @field IN [val1, val2, val3]

The parser builds an Abstract Syntax Tree (AST) that can be evaluated against spans.
"""

import re
from typing import Any, Dict, List, Optional


# ============================================================================
# AST Node Classes
# ============================================================================


class QueryNode:
    """Base class for query AST nodes."""

    def evaluate(self, span: Dict[str, Any], span_matcher) -> bool:
        """Evaluate this node against a span.

        Args:
            span: The span dictionary to match against
            span_matcher: Object with helper methods for field extraction and matching
        """
        raise NotImplementedError


class FilterNode(QueryNode):
    """Leaf node representing a single filter condition."""

    def __init__(self, filter_dict: Dict[str, Any]):
        self.filter = filter_dict

    def evaluate(self, span: Dict[str, Any], span_matcher) -> bool:
        """Evaluate a single filter against a span."""
        field = self.filter["field"]
        filter_type = self.filter.get("type", "facet")
        operator = self.filter.get("operator")
        is_negated = self.filter.get("not", False)

        # Handle existence queries
        if operator == "exists":
            result = span_matcher.field_exists(span, field)
            return not result if is_negated else result

        if operator == "missing":
            result = not span_matcher.field_exists(span, field)
            return not result if is_negated else result

        # Get span field value
        if filter_type == "tag":
            span_value = span_matcher.get_tag_value(span, field)
        else:
            span_value = span_matcher.get_field_value(span, field)

        if span_value is None:
            return is_negated  # No value: fail match (or succeed if negated)

        # Handle different operators
        if operator == "range":
            result = self._match_range(span_value)
        elif operator in ("gte", "lte", "gt", "lt"):
            result = self._match_comparison(span_value, operator)
        elif operator == "in":
            result = self._match_in(span_value)
        else:
            # Default: wildcard matching
            result = self._match_wildcard(span_value, span_matcher)

        return not result if is_negated else result

    def _match_range(self, span_value) -> bool:
        """Match range operator."""
        try:
            num = float(span_value)
            if self.filter.get("min") is not None and num < self.filter["min"]:
                return False
            if self.filter.get("max") is not None and num > self.filter["max"]:
                return False
            return True
        except (ValueError, TypeError):
            return False

    def _match_comparison(self, span_value, operator: str) -> bool:
        """Match comparison operators (>, <, >=, <=)."""
        if self.filter.get("value") is None:
            return False
        try:
            num = float(span_value)
            cmp = self.filter["value"]
            if operator == "gte":
                return num >= cmp
            elif operator == "lte":
                return num <= cmp
            elif operator == "gt":
                return num > cmp
            elif operator == "lt":
                return num < cmp
            return False
        except (ValueError, TypeError):
            return False

    def _match_in(self, span_value) -> bool:
        """Match IN operator."""
        values = self.filter.get("values", [])
        return str(span_value) in values

    def _match_wildcard(self, span_value, span_matcher) -> bool:
        """Match wildcard pattern."""
        value = self.filter.get("value")
        if value is None or value == "*":
            return True
        return span_matcher.match_wildcard(str(span_value), str(value))


class BooleanNode(QueryNode):
    """Node representing AND or OR operation."""

    def __init__(self, operator: str, children: List[QueryNode]):
        self.operator = operator.upper()  # "AND" or "OR"
        self.children = children

    def evaluate(self, span: Dict[str, Any], span_matcher) -> bool:
        """Evaluate boolean operation."""
        if self.operator == "AND":
            # Short-circuit: return False on first False
            return all(child.evaluate(span, span_matcher) for child in self.children)
        elif self.operator == "OR":
            # Short-circuit: return True on first True
            return any(child.evaluate(span, span_matcher) for child in self.children)
        else:
            return False


class NotNode(QueryNode):
    """Node representing NOT operation."""

    def __init__(self, child: QueryNode):
        self.child = child

    def evaluate(self, span: Dict[str, Any], span_matcher) -> bool:
        """Evaluate NOT operation."""
        return not self.child.evaluate(span, span_matcher)


# ============================================================================
# Query Tokenizer
# ============================================================================


def tokenize_query(query: str) -> List[str]:
    """Tokenize query string into tokens.

    Handles:
    - Parentheses
    - Boolean operators (AND, OR, NOT)
    - Filters (@field:value, field:value)
    - Quoted strings
    - Escaped characters
    - Brackets for ranges and IN operator

    Examples:
        >>> tokenize_query("@status:error AND env:prod")
        ['@status:error', 'AND', 'env:prod']

        >>> tokenize_query("(env:prod OR env:staging) AND @status:error")
        ['(', 'env:prod', 'OR', 'env:staging', ')', 'AND', '@status:error']
    """
    tokens = []
    current = []
    i = 0
    in_quotes = False
    in_brackets = False

    while i < len(query):
        char = query[i]

        # Handle escape sequences
        if char == "\\" and i + 1 < len(query):
            current.append(char)
            current.append(query[i + 1])
            i += 2
            continue

        # Handle quotes
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            i += 1
            continue

        # Handle brackets for ranges and IN operator
        if char == "[":
            in_brackets = True
            current.append(char)
            i += 1
            continue

        if char == "]":
            in_brackets = False
            current.append(char)
            i += 1
            continue

        # Don't split inside quotes or brackets
        if in_quotes or in_brackets:
            current.append(char)
            i += 1
            continue

        # Handle parentheses
        if char in "()":
            if current:
                tokens.append("".join(current).strip())
                current = []
            tokens.append(char)
            i += 1
            continue

        # Handle whitespace
        if char.isspace():
            if current:
                token = "".join(current).strip()
                if token:
                    tokens.append(token)
                current = []
            i += 1
            continue

        # Handle - as NOT operator when at the start of a new token
        # e.g. "-env:dev" should tokenize as ["-", "env:dev"] not ["-env:dev"]
        if char == "-" and not current:
            tokens.append("-")
            i += 1
            continue

        current.append(char)
        i += 1

    # Add final token
    if current:
        token = "".join(current).strip()
        if token:
            tokens.append(token)

    return tokens


# ============================================================================
# Query Parser (Builds AST)
# ============================================================================


def parse_query_to_ast(query: str, duration_parser=None) -> Optional[QueryNode]:
    """Parse query string into an AST.

    Operator precedence (highest to lowest):
    1. Parentheses ()
    2. NOT
    3. AND (implicit or explicit)
    4. OR

    Args:
        query: The query string to parse
        duration_parser: Function to parse duration strings (e.g., "100ms" -> nanoseconds)

    Returns:
        Root QueryNode of the AST, or None if query is empty

    Examples:
        >>> ast = parse_query_to_ast("@status:error AND env:prod")
        >>> ast = parse_query_to_ast("(env:prod OR env:staging) AND @status:error")
        >>> ast = parse_query_to_ast("NOT @model_name:gpt-3.5-turbo")
    """
    if not query or not query.strip():
        return None

    tokens = tokenize_query(query)
    if not tokens:
        return None

    ast, _ = _parse_or(tokens, 0, duration_parser)
    return ast


def _parse_or(tokens: List[str], pos: int, duration_parser) -> tuple[Optional[QueryNode], int]:
    """Parse OR expression (lowest precedence)."""
    left, pos = _parse_and(tokens, pos, duration_parser)
    if left is None:
        return None, pos

    # Collect OR operands
    or_operands = [left]
    while pos < len(tokens) and tokens[pos].upper() == "OR":
        pos += 1  # Skip OR
        right, pos = _parse_and(tokens, pos, duration_parser)
        if right is None:
            break
        or_operands.append(right)

    if len(or_operands) == 1:
        return or_operands[0], pos
    return BooleanNode("OR", or_operands), pos


def _parse_and(tokens: List[str], pos: int, duration_parser) -> tuple[Optional[QueryNode], int]:
    """Parse AND expression (medium precedence).

    Supports both explicit AND and implicit AND (adjacent terms).
    """
    left, pos = _parse_not(tokens, pos, duration_parser)
    if left is None:
        return None, pos

    # Collect AND operands (explicit AND or implicit)
    and_operands = [left]
    while pos < len(tokens):
        # Explicit AND
        if tokens[pos].upper() == "AND":
            pos += 1  # Skip AND
            right, pos = _parse_not(tokens, pos, duration_parser)
            if right is None:
                break
            and_operands.append(right)
        # Implicit AND: next token is not a boolean operator or closing paren
        elif tokens[pos].upper() not in ("OR", "AND") and tokens[pos] != ")":
            right, pos = _parse_not(tokens, pos, duration_parser)
            if right is None:
                break
            and_operands.append(right)
        else:
            break

    if len(and_operands) == 1:
        return and_operands[0], pos
    return BooleanNode("AND", and_operands), pos


def _parse_not(tokens: List[str], pos: int, duration_parser) -> tuple[Optional[QueryNode], int]:
    """Parse NOT expression (high precedence)."""
    if pos >= len(tokens):
        return None, pos

    # Check for NOT or - prefix
    if tokens[pos].upper() == "NOT" or tokens[pos] == "-":
        pos += 1  # Skip NOT/-
        child, pos = _parse_primary(tokens, pos, duration_parser)
        if child is None:
            return None, pos
        return NotNode(child), pos

    return _parse_primary(tokens, pos, duration_parser)


def _parse_primary(tokens: List[str], pos: int, duration_parser) -> tuple[Optional[QueryNode], int]:
    """Parse primary expression (parentheses or filter)."""
    if pos >= len(tokens):
        return None, pos

    token = tokens[pos]

    # Handle parentheses
    if token == "(":
        pos += 1  # Skip (
        node, pos = _parse_or(tokens, pos, duration_parser)  # Parse inner expression
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1  # Skip )
        return node, pos

    # Handle _exists_ and _missing_
    if token.startswith("_exists_:"):
        field = token[9:].lstrip("@")
        filter_dict = {"field": field, "type": "exists", "operator": "exists"}
        return FilterNode(filter_dict), pos + 1

    if token.startswith("_missing_:"):
        field = token[10:].lstrip("@")
        filter_dict = {"field": field, "type": "missing", "operator": "missing"}
        return FilterNode(filter_dict), pos + 1

    # Check for IN operator first: @field IN [val1, val2, ...]
    if pos + 2 < len(tokens) and tokens[pos + 1].upper() == "IN":
        values_token = tokens[pos + 2]
        if values_token.startswith("[") and values_token.endswith("]"):
            # Extract field name
            if token.startswith("@"):
                field = token[1:]  # Remove @
                filter_type = "facet"
            else:
                field = token
                filter_type = "tag"

            # Parse values
            values_str = values_token[1:-1]
            values = [v.strip().strip('"\'') for v in values_str.split(",")]

            filter_dict = {
                "field": field,
                "type": filter_type,
                "operator": "in",
                "values": values
            }
            return FilterNode(filter_dict), pos + 3

    # Try to parse as filter
    filter_dict = _parse_filter_token(token, tokens, pos, duration_parser)
    if filter_dict:
        return FilterNode(filter_dict), pos + 1

    # Skip unknown token
    return None, pos + 1


def _parse_filter_token(
    token: str, tokens: List[str], pos: int, duration_parser
) -> Optional[Dict[str, Any]]:
    """Parse a single filter token into a filter dictionary.

    Supports:
    - Range: @field:[min TO max]
    - Comparison: @field:>value, @field:>=value, etc.
    - Facet: @field:value
    - Tag: field:value
    """
    # Range filter: @field:[min TO max]
    match = re.match(r"@([\w.]+):\[([^\]]+)\s+TO\s+([^\]]+)\]", token, re.IGNORECASE)
    if match:
        field, min_val, max_val = match.groups()
        f: Dict[str, Any] = {"field": field, "type": "facet", "operator": "range"}

        # Special handling for duration field
        if field == "duration" and duration_parser:
            min_ns = duration_parser(min_val.strip())
            max_ns = duration_parser(max_val.strip())
            if min_ns is not None:
                f["min"] = min_ns
            if max_ns is not None:
                f["max"] = max_ns
        else:
            # Try to parse as numbers
            try:
                f["min"] = float(min_val.strip())
            except ValueError:
                f["min"] = min_val.strip()
            try:
                f["max"] = float(max_val.strip())
            except ValueError:
                f["max"] = max_val.strip()
        return f

    # Comparison filter: @field:>=value, @field:<value, etc.
    match = re.match(r"@([\w.]+):(>=|<=|>|<)(.+)", token)
    if match:
        field, op, value = match.groups()
        op_map = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
        f = {"field": field, "type": "facet", "operator": op_map[op]}

        # Special handling for duration field
        if field == "duration" and duration_parser:
            parsed = duration_parser(value)
            if parsed is not None:
                f["value"] = parsed
        else:
            # Try to parse as number
            try:
                f["value"] = float(value)
            except ValueError:
                f["value"] = value
        return f

    # Facet filter: @field:value
    if token.startswith("@") and ":" in token:
        parts = token.split(":", 1)
        if len(parts) == 2:
            field = parts[0][1:]  # Remove @
            value = parts[1]
            return {"field": field, "value": value, "type": "facet"}

    # Tag filter: field:value (without @)
    if ":" in token and not token.startswith("@") and not token.startswith("_"):
        parts = token.split(":", 1)
        if len(parts) == 2:
            field, value = parts
            return {"field": field, "value": value, "type": "tag"}

    return None


# ============================================================================
# Helper Functions
# ============================================================================


def match_wildcard(value: str, pattern: str, case_sensitive: bool = True) -> bool:
    """Match value against pattern with wildcard support.

    Supports:
    - * : matches zero or more characters
    - ? : matches exactly one character

    Args:
        value: The value to match
        pattern: The pattern with wildcards
        case_sensitive: Whether to perform case-sensitive matching (default: True)

    Examples:
        >>> match_wildcard("gpt-4", "gpt*")
        True
        >>> match_wildcard("gpt-4", "*-4")
        True
        >>> match_wildcard("gpt-4", "*gpt*")
        True
        >>> match_wildcard("user1", "user?")
        True
        >>> match_wildcard("user10", "user?")
        False
    """
    if not case_sensitive:
        value = value.lower()
        pattern = pattern.lower()

    # Fast path: exact match (no wildcards)
    if "*" not in pattern and "?" not in pattern:
        return value == pattern

    # Fast path: match everything
    if pattern == "*":
        return True

    # Fast path: contains (*substring*)
    if pattern.startswith("*") and pattern.endswith("*") and pattern.count("*") == 2:
        return pattern[1:-1] in value

    # Fast path: suffix match (*suffix)
    if pattern.startswith("*") and "*" not in pattern[1:] and "?" not in pattern:
        return value.endswith(pattern[1:])

    # Fast path: prefix match (prefix*)
    if pattern.endswith("*") and "*" not in pattern[:-1] and "?" not in pattern:
        return value.startswith(pattern[:-1])

    # Slow path: recursive matching with both * and ?
    return _match_wildcard_recursive(value, pattern, 0, 0)


def _match_wildcard_recursive(value: str, pattern: str, v_idx: int, p_idx: int) -> bool:
    """Recursively match wildcard pattern."""
    # Base case: both exhausted
    if v_idx == len(value) and p_idx == len(pattern):
        return True

    # Pattern exhausted but value remains
    if p_idx == len(pattern):
        return False

    # Handle * wildcard
    if pattern[p_idx] == "*":
        # Try matching * with 0 characters, 1 character, 2 characters, etc.
        for i in range(v_idx, len(value) + 1):
            if _match_wildcard_recursive(value, pattern, i, p_idx + 1):
                return True
        return False

    # Handle ? wildcard
    if pattern[p_idx] == "?":
        # ? must match exactly one character
        if v_idx >= len(value):
            return False
        return _match_wildcard_recursive(value, pattern, v_idx + 1, p_idx + 1)

    # Handle literal character
    if v_idx >= len(value) or value[v_idx] != pattern[p_idx]:
        return False

    return _match_wildcard_recursive(value, pattern, v_idx + 1, p_idx + 1)
