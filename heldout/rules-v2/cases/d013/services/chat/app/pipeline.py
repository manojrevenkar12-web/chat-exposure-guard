import logging
import time

from anthropic import AsyncAnthropic

from .memory import extract_memories, save_memories
from .prompts import SYSTEM_PROMPT

logger = logging.getLogger("chat.pipeline")
client = AsyncAnthropic()


async def handle_turn(conversation_id: str, user_id: int, text: str, history: list[dict]) -> str:
    started = time.monotonic()
    logger.info("turn received conversation=%s chars=%d", conversation_id, len(text))

    response = await client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=history + [{"role": "user", "content": text}],
    )
    reply = response.content[0].text
    logger.info(
        "reply generated conversation=%s chars=%d in_tokens=%d out_tokens=%d ms=%d",
        conversation_id,
        len(reply),
        response.usage.input_tokens,
        response.usage.output_tokens,
        int((time.monotonic() - started) * 1000),
    )

    memories = await extract_memories(text, reply)
    await save_memories(user_id, memories)
    print(f"stored {len(memories)} memories for user {user_id}")
    return reply
