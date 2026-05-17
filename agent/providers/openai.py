from dataclasses import dataclass

from agent.config import require_openai_api_key


def get_openai_module():
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("openai is not installed. Install project dependencies first.") from exc
    return OpenAI


@dataclass(frozen=True)
class OpenAIProvider:
    model: str
    name: str = "openai"

    def get_client(self):
        OpenAI = get_openai_module()
        return OpenAI(api_key=require_openai_api_key())

    def generate(self, prompt: str, *, temperature: float, max_output_tokens: int) -> str:
        response = self.get_client().responses.create(
            model=self.model,
            input=prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
        return (response.output_text or "").strip()
