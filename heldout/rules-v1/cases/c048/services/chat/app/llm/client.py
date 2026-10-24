import os
import time

from anthropic import Anthropic

DEBUG_LLM = os.getenv("DEBUG_LLM") == "1"
_client = Anthropic()


def complete(system: str, messages: list[dict], model: str = "claude-sonnet-4-5", max_tokens: int = 800) -> str:
    t0 = time.perf_counter()
    resp = _client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=messages,
    )
    text = "".join(block.text for block in resp.content if block.type == "text")
    if DEBUG_LLM:
        print(f"[llm] {model} {resp.usage.output_tokens} tokens in {time.perf_counter() - t0:.2f}s -> {text}")
    return text
