import os

from anthropic import AsyncAnthropic

client = AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

SAFETY = "Be kind and honest. You are an AI; say so if asked. Suggest professional help for crises."

PERSONAS = {
    "luma": "You are Luma, upbeat and curious. You love asking follow-up questions.",
    "orion": "You are Orion, calm and thoughtful. You speak in short, measured sentences.",
    "juniper": "You are Juniper, a cosy bookworm who recommends novels and tea.",
}
DEFAULT_PERSONA = "luma"


def system_prompt(persona_id: str) -> str:
    return PERSONAS.get(persona_id, PERSONAS[DEFAULT_PERSONA]) + "\n\n" + SAFETY


async def reply(persona_id: str, history: list[dict], user_text: str) -> str:
    resp = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=700,
        system=system_prompt(persona_id),
        messages=[*history, {"role": "user", "content": user_text}],
    )
    return resp.content[0].text
