import os

from anthropic import AsyncAnthropic

from app.models import Character, Message

client = AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

BASE_RULES = "Stay in character. Be kind. Do not give medical, legal or financial advice."


def system_for(character: Character) -> str:
    # community characters: name, greeting and description come from the creator's form
    return (
        f"You are {character.name}.\n"
        f"{character.description}\n\n"
        f"Greeting style: {character.greeting}\n\n"
        f"{BASE_RULES}"
    )


async def reply(character: Character, history: list[Message]) -> str:
    resp = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=800,
        system=system_for(character),
        messages=[{"role": m.role, "content": m.body} for m in history],
    )
    return resp.content[0].text
