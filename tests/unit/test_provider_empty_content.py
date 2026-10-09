from fmb.interpretation.provider import _missing_content_error


def test_openrouter_empty_answer_carries_its_usage_like_openai():
    raw = {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}],
           "usage": {"prompt_tokens": 1000, "completion_tokens": 50, "total_tokens": 1050}}
    error = _missing_content_error("OpenRouter", raw)
    assert error.details["retryable"] is False
    assert error.details["usage"]["input_tokens"] == 1000
    assert error.details["usage"]["output_tokens"] == 50


def test_transient_upstream_error_stays_a_transport_failure():
    raw = {"error": {"code": 502, "message": "upstream unavailable"},
           "usage": {"prompt_tokens": 0, "completion_tokens": 0}}
    error = _missing_content_error("OpenRouter", raw)
    assert error.details["retryable"] is True
    assert "usage" not in error.details
