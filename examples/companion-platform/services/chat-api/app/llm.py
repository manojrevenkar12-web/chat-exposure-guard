from anthropic import AsyncAnthropic

from .memory import memories_for

client = AsyncAnthropic()
SYSTEM = "You are a warm, playful companion. Stay in character."


async def reply_to(user, conv, message):
    memories = await memories_for(user.id)
    character = conv.character
    system = SYSTEM + "\nCharacter: " + character.description + "\nWhat you remember: " + "; ".join(memories)
    msgs = [{"role": "user", "content": message.content}]
    resp = await client.messages.create(model="claude-sonnet", max_tokens=600, system=system, messages=msgs)
    return resp.content[0].text
