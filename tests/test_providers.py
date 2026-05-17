import pytest

from agent import config
from agent.providers.factory import get_provider
from agent.providers.fallback import FallbackProvider
from agent.providers.gemini import GeminiProvider
from agent.providers.openai import OpenAIProvider


def test_get_provider_defaults_to_configured_openai_with_gemini_fallback(monkeypatch):
    monkeypatch.setattr(config, "PROVIDER", "openai")
    monkeypatch.setattr(config, "MODEL", "gpt-4.1-mini")

    provider = get_provider()

    assert isinstance(provider, FallbackProvider)
    assert isinstance(provider.primary, OpenAIProvider)
    assert isinstance(provider.fallback, GeminiProvider)
    assert provider.model == "gpt-4.1-mini"


def test_get_provider_supports_openai(monkeypatch):
    monkeypatch.setattr(config, "PROVIDER", "openai")
    monkeypatch.setattr(config, "MODEL", "gpt-4.1-mini")

    provider = get_provider()

    assert isinstance(provider, FallbackProvider)
    assert isinstance(provider.primary, OpenAIProvider)
    assert provider.model == "gpt-4.1-mini"


def test_get_provider_supports_explicit_gemini(monkeypatch):
    monkeypatch.setattr(config, "PROVIDER", "gemini")
    monkeypatch.setattr(config, "MODEL", "gemini-2.5-flash")

    provider = get_provider()

    assert isinstance(provider, GeminiProvider)
    assert provider.model == "gemini-2.5-flash"


def test_fallback_provider_uses_fallback_when_primary_fails():
    class BrokenProvider:
        name = "broken"
        model = "broken-model"

        def generate(self, prompt, *, temperature, max_output_tokens):
            raise RuntimeError("provider failed")

    class WorkingProvider:
        name = "working"
        model = "working-model"

        def generate(self, prompt, *, temperature, max_output_tokens):
            return f"{prompt}: ok"

    provider = FallbackProvider(primary=BrokenProvider(), fallback=WorkingProvider())

    assert provider.generate("test", temperature=0.1, max_output_tokens=16) == "test: ok"


def test_get_provider_rejects_unknown_provider():
    with pytest.raises(RuntimeError, match="Unsupported NETADMIN_PROVIDER"):
        get_provider("unknown")
