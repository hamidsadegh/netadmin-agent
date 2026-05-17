from dataclasses import dataclass

from agent.config import require_gemini_api_key


def get_genai_modules():
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("google-genai is not installed. Install project dependencies first.") from exc
    return genai, types


@dataclass(frozen=True)
class GeminiProvider:
    model: str
    name: str = "gemini"

    def get_client(self):
        genai, _ = get_genai_modules()
        return genai.Client(api_key=require_gemini_api_key())

    def generate(self, prompt: str, *, temperature: float, max_output_tokens: int) -> str:
        _, types = get_genai_modules()
        response = self.get_client().models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            ),
        )
        return (response.text or "").strip()
