"""Tests for LLM Observability Query Parser with Boolean Logic."""

import pytest

from ddapm_test_agent.llmobs_event_platform import apply_filters
from ddapm_test_agent.llmobs_event_platform import parse_filter_query

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_spans():
    """Sample spans for testing query matching."""
    return [
        {
            "name": "llm-call-1",
            "span_id": "span-1",
            "status": "ok",
            "duration": 1_500_000_000,  # 1.5s in nanoseconds
            "meta": {
                "model_name": "gpt-4",
                "model_provider": "openai",
                "span": {"kind": "llm"},
            },
            "metrics": {"tokens": 1000},
            "tags": ["env:prod", "service:api", "version:1.0"],
        },
        {
            "name": "llm-call-2",
            "span_id": "span-2",
            "status": "error",
            "duration": 500_000_000,  # 0.5s
            "meta": {
                "model_name": "gpt-3.5-turbo",
                "model_provider": "openai",
                "span": {"kind": "llm"},
            },
            "metrics": {"tokens": 500},
            "tags": ["env:staging", "service:web", "version:1.0"],
        },
        {
            "name": "agent-workflow",
            "span_id": "span-3",
            "status": "ok",
            "duration": 3_000_000_000,  # 3s
            "meta": {
                "span": {"kind": "agent"},
            },
            "metrics": {"tokens": 2000},
            "tags": ["env:prod", "service:api", "version:2.0"],
        },
        {
            "name": "embedding-call",
            "span_id": "span-4",
            "status": "ok",
            "duration": 200_000_000,  # 0.2s
            "meta": {
                "model_name": "text-embedding-ada-002",
                "model_provider": "openai",
                "span": {"kind": "embedding"},
            },
            "metrics": {"tokens": 100},
            "tags": ["env:dev", "service:api"],
        },
    ]


# ============================================================================
# Test Basic Filters (No Boolean Operators)
# ============================================================================


def test_simple_attribute_filter(sample_spans):
    """Test simple attribute filter @field:value."""
    query = "@meta.model_name:gpt-4"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 1
    assert result[0]["span_id"] == "span-1"


def test_simple_tag_filter(sample_spans):
    """Test simple tag filter field:value."""
    query = "env:prod"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"


def test_implicit_and_filter(sample_spans):
    """Test implicit AND (space-separated filters)."""
    query = "env:prod service:api"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"


def test_wildcard_star_filter(sample_spans):
    """Test * wildcard matching."""
    query = "@meta.model_name:gpt*"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-2"


def test_wildcard_question_mark(sample_spans):
    """Test ? single-character wildcard matching."""
    query = "@meta.model_name:gpt-?"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # Should match "gpt-4" but not "gpt-3.5-turbo"
    assert len(result) == 1
    assert result[0]["span_id"] == "span-1"


# ============================================================================
# Test Boolean Operators
# ============================================================================


def test_explicit_and_operator(sample_spans):
    """Test explicit AND operator."""
    query = "env:prod AND service:api"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"


def test_or_operator(sample_spans):
    """Test OR operator."""
    query = "env:prod OR env:staging"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-2" in span_ids
    assert "span-3" in span_ids


def test_not_operator_dash(sample_spans):
    """Test NOT operator with - prefix."""
    query = "-env:dev"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-4" not in span_ids


def test_not_operator_keyword(sample_spans):
    """Test NOT operator with NOT keyword."""
    query = "NOT env:dev"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-4" not in span_ids


def test_and_with_not(sample_spans):
    """Test AND combined with NOT."""
    query = "env:prod AND -service:web"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"


# ============================================================================
# Test Parentheses Grouping
# ============================================================================


def test_parentheses_or_and(sample_spans):
    """Test (A OR B) AND C."""
    query = "(env:prod OR env:staging) AND service:api"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"


def test_parentheses_complex(sample_spans):
    """Test complex parentheses: (A OR B) AND (C OR D)."""
    query = "(env:prod OR env:staging) AND (@status:error OR version:2.0)"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    span_ids = [s["span_id"] for s in result]
    assert "span-2" in span_ids  # staging + error
    assert "span-3" in span_ids  # prod + version:2.0


def test_nested_parentheses(sample_spans):
    """Test nested parentheses."""
    query = "((env:prod OR env:staging) AND service:api) OR env:dev"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids  # prod + api
    assert "span-3" in span_ids  # prod + api
    assert "span-4" in span_ids  # dev


# ============================================================================
# Test Comparison Operators
# ============================================================================


def test_greater_than(sample_spans):
    """Test > comparison operator."""
    query = "@duration:>1000000000"  # > 1s
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids  # 1.5s
    assert "span-3" in span_ids  # 3s


def test_less_than_or_equal(sample_spans):
    """Test <= comparison operator."""
    query = "@metrics.tokens:<=1000"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids  # 1000
    assert "span-2" in span_ids  # 500
    assert "span-4" in span_ids  # 100


def test_range_query(sample_spans):
    """Test range query [min TO max]."""
    query = "@duration:[500000000 TO 2000000000]"  # 0.5s to 2s
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids  # 1.5s
    assert "span-2" in span_ids  # 0.5s


# ============================================================================
# Test Existence Queries
# ============================================================================


def test_exists_query(sample_spans):
    """Test _exists_ operator."""
    query = "_exists_:@meta.model_name"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 3
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-2" in span_ids
    assert "span-4" in span_ids


def test_missing_query(sample_spans):
    """Test _missing_ operator."""
    query = "_missing_:@meta.model_name"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 1
    assert result[0]["span_id"] == "span-3"


# ============================================================================
# Test IN Operator
# ============================================================================


def test_in_operator(sample_spans):
    """Test IN operator."""
    query = "@status IN [error, warning]"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 1
    assert result[0]["span_id"] == "span-2"


# ============================================================================
# Test Complex Real-World Queries
# ============================================================================


def test_production_error_query(sample_spans):
    """Test: Find errors in production, excluding specific services."""
    query = "env:prod AND @status:error AND -service:web"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # No production errors matching this criteria
    assert len(result) == 0


def test_slow_requests_query(sample_spans):
    """Test: Find slow requests to specific services."""
    query = "(service:api OR service:web) AND @duration:>1000000000"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-3" in span_ids


def test_model_filtering_query(sample_spans):
    """Test: Find spans using old models or specific providers."""
    query = "(@meta.model_name:gpt-3* OR @meta.model_name:text*) AND env:prod OR env:staging"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # This should match span-2 (gpt-3.5-turbo in staging)
    assert len(result) >= 1
    span_ids = [s["span_id"] for s in result]
    assert "span-2" in span_ids


def test_cost_analysis_query(sample_spans):
    """Test: Find high-token usage across multiple environments."""
    query = "(env:prod OR env:staging) AND @metrics.tokens:>500"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 2
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids  # prod, 1000 tokens
    assert "span-3" in span_ids  # prod, 2000 tokens


# ============================================================================
# Test Edge Cases
# ============================================================================


def test_empty_query(sample_spans):
    """Test empty query returns all spans."""
    query = ""
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 4


def test_no_matches(sample_spans):
    """Test query with no matches."""
    query = "env:production"  # Typo, should be "prod"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 0


def test_all_or_query(sample_spans):
    """Test OR with all possible values."""
    query = "env:prod OR env:staging OR env:dev OR env:test"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    assert len(result) == 4


def test_contradictory_and(sample_spans):
    """Test contradictory AND condition."""
    query = "env:prod AND env:staging"
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # A span cannot have both tags
    assert len(result) == 0


# ============================================================================
# Test Case Sensitivity
# ============================================================================


def test_case_sensitive_matching(sample_spans):
    """Test that wildcard matching is case-sensitive."""
    query = "@meta.model_name:GPT-4"  # Wrong case
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # Should not match "gpt-4" (case-sensitive)
    assert len(result) == 0


def test_case_sensitive_wildcard(sample_spans):
    """Test that wildcard matching is case-sensitive."""
    query = "@meta.model_name:GPT*"  # Wrong case
    parsed = parse_filter_query(query)
    result = apply_filters(sample_spans, parsed)

    # Should not match "gpt-4" or "gpt-3.5-turbo" (case-sensitive)
    assert len(result) == 0
