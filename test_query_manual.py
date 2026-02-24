"""Manual test script for query parser (without pytest)."""

from ddapm_test_agent.llmobs_event_platform import parse_filter_query, apply_filters


def get_sample_spans():
    """Create sample spans for testing."""
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


def test_simple_attribute_filter():
    """Test simple attribute filter @field:value."""
    spans = get_sample_spans()
    query = "@meta.model_name:gpt-4"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert result[0]["span_id"] == "span-1"
    print("✓ test_simple_attribute_filter passed")


def test_simple_tag_filter():
    """Test simple tag filter field:value."""
    spans = get_sample_spans()
    query = "env:prod"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"
    print("✓ test_simple_tag_filter passed")


def test_implicit_and():
    """Test implicit AND (space-separated)."""
    spans = get_sample_spans()
    query = "env:prod service:api"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    print("✓ test_implicit_and passed")


def test_wildcard_star():
    """Test * wildcard."""
    spans = get_sample_spans()
    query = "@meta.model_name:gpt*"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    print("✓ test_wildcard_star passed")


def test_wildcard_question():
    """Test ? single-char wildcard."""
    spans = get_sample_spans()
    query = "@meta.model_name:gpt-?"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 1, f"Expected 1 result (gpt-4), got {len(result)}"
    assert result[0]["span_id"] == "span-1"
    print("✓ test_wildcard_question passed")


def test_or_operator():
    """Test OR operator."""
    spans = get_sample_spans()
    query = "env:prod OR env:staging"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 3, f"Expected 3 results, got {len(result)}"
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-2" in span_ids
    assert "span-3" in span_ids
    print("✓ test_or_operator passed")


def test_not_operator():
    """Test NOT operator."""
    spans = get_sample_spans()
    query = "NOT env:dev"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 3, f"Expected 3 results, got {len(result)}"
    span_ids = [s["span_id"] for s in result]
    assert "span-4" not in span_ids
    print("✓ test_not_operator passed")


def test_parentheses_or_and():
    """Test (A OR B) AND C."""
    spans = get_sample_spans()
    query = "(env:prod OR env:staging) AND service:api"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    assert result[0]["span_id"] == "span-1"
    assert result[1]["span_id"] == "span-3"
    print("✓ test_parentheses_or_and passed")


def test_comparison_gt():
    """Test > comparison."""
    spans = get_sample_spans()
    query = "@duration:>1000000000"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-3" in span_ids
    print("✓ test_comparison_gt passed")


def test_range_query():
    """Test range query."""
    spans = get_sample_spans()
    query = "@duration:[500000000 TO 2000000000]"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    span_ids = [s["span_id"] for s in result]
    assert "span-1" in span_ids
    assert "span-2" in span_ids
    print("✓ test_range_query passed")


def test_exists_query():
    """Test _exists_ operator."""
    spans = get_sample_spans()
    query = "_exists_:@meta.model_name"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 3, f"Expected 3 results, got {len(result)}"
    print("✓ test_exists_query passed")


def test_missing_query():
    """Test _missing_ operator."""
    spans = get_sample_spans()
    query = "_missing_:@meta.model_name"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert result[0]["span_id"] == "span-3"
    print("✓ test_missing_query passed")


def test_in_operator():
    """Test IN operator."""
    spans = get_sample_spans()
    query = "@status IN [error,warning]"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert result[0]["span_id"] == "span-2"
    print("✓ test_in_operator passed")


def test_complex_query():
    """Test complex real-world query."""
    spans = get_sample_spans()
    query = "(service:api OR service:web) AND @duration:>1000000000"
    parsed = parse_filter_query(query)
    result = apply_filters(spans, parsed)

    assert len(result) == 2, f"Expected 2 results, got {len(result)}"
    print("✓ test_complex_query passed")


if __name__ == "__main__":
    print("Running query parser tests...\n")

    try:
        test_simple_attribute_filter()
        test_simple_tag_filter()
        test_implicit_and()
        test_wildcard_star()
        test_wildcard_question()
        test_or_operator()
        test_not_operator()
        test_parentheses_or_and()
        test_comparison_gt()
        test_range_query()
        test_exists_query()
        test_missing_query()
        test_in_operator()
        test_complex_query()

        print("\n✅ All tests passed!")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
