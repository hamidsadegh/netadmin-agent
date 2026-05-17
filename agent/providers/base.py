from typing import Protocol


class LLMProvider(Protocol):
    name: str
    model: str

    def generate(self, prompt: str, *, temperature: float, max_output_tokens: int) -> str:
        """Return text from a provider-specific model."""
