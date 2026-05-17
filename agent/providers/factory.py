from agent import config
from agent.providers.base import LLMProvider
from agent.providers.fallback import FallbackProvider
from agent.providers.gemini import GeminiProvider
from agent.providers.openai import OpenAIProvider


def get_provider(provider_name: str | None = None, model: str | None = None) -> LLMProvider:
    provider = (provider_name or config.PROVIDER).strip().lower()
    selected_model = model or config.MODEL

    if provider == "gemini":
        return GeminiProvider(model=selected_model)
    if provider == "openai":
        return FallbackProvider(
            primary=OpenAIProvider(model=selected_model),
            fallback=GeminiProvider(model=config.DEFAULT_MODELS["gemini"]),
        )

    supported = ", ".join(("gemini", "openai"))
    raise RuntimeError(f"Unsupported NETADMIN_PROVIDER {provider!r}. Supported providers: {supported}.")
