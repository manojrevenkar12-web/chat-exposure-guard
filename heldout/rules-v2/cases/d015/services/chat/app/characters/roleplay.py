from anthropic import AsyncAnthropic

from ..db import get_character
from ..settings import settings

client = AsyncAnthropic(api_key=settings.anthropic_api_key)


async def roleplay_reply(character_id: int, history: list[dict]) -> str:
    character = await get_character(character_id)
    system = (
        f"You are {character.name}. {character.description}\n\n"
        f"Your usual greeting is: {character.greeting}\n"
        "Stay in character and keep the conversation friendly."
    )
    resp = await client.messages.create(
        model=settings.chat_model,
        max_tokens=700,
        system=system,
        messages=history,
    )
    return resp.content[0].text
