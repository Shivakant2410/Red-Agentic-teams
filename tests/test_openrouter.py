import io
import json

from agentic_setup.openrouter import OpenRouterClient


def test_completion_enforces_zero_price_provider_route(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return io.BytesIO(
            json.dumps(
                {
                    "id": "response-1",
                    "model": "vendor/model:free",
                    "choices": [
                        {"message": {"content": "safe", "role": "assistant"}}
                    ],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1, "cost": 0},
                }
            ).encode("utf-8")
        )

    monkeypatch.setattr("agentic_setup.openrouter.urlopen", fake_urlopen)
    result = OpenRouterClient(api_key="test-key").complete(
        "vendor/model:free",
        [{"role": "user", "content": "hello"}],
    )

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))
    assert payload["provider"]["max_price"] == {"prompt": 0, "completion": 0}
    assert request.get_header("Authorization") == "Bearer test-key"
    assert result.content == "safe"
