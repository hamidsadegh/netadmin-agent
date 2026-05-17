from dataclasses import dataclass

from agent.providers.base import LLMProvider


@dataclass(frozen=True)
class FallbackProvider:
    primary: LLMProvider
    fallback: LLMProvider
    name: str = "fallback"

    @property
    def model(self) -> str:
        return self.primary.model

    def get_client(self):
        return self.primary.get_client()

    def generate(self, prompt: str, *, temperature: float, max_output_tokens: int) -> str:
        try:
            return self.primary.generate(
                prompt,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            )
        except Exception:
            return self.fallback.generate(
                prompt,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            )
