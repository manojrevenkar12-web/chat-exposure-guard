from openai import OpenAI

from .prompts import PromptBuilder
from .repo import load_profile, recent_turns

client = OpenAI()


def respond(user_id: int, conversation_id: str, text: str) -> str:
    builder = PromptBuilder(load_profile(user_id))
    turns = recent_turns(conversation_id, limit=16)
    response = client.responses.create(
        model="gpt-4.1-mini",
        instructions=builder.build_instructions(),
        input=turns + [{"role": "user", "content": text}],
        max_output_tokens=500,
    )
    return response.output_text
