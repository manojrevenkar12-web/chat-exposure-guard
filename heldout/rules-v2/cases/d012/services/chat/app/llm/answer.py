import structlog
from openai import AsyncOpenAI

from ..memory.store import MemoryStore
from ..models import Conversation

log = structlog.get_logger(__name__)
client = AsyncOpenAI()

SYSTEM_BASE = (
    "You are Theo, a friendly companion who remembers past conversations. "
    "Be supportive and concise."
)


async def answer(user_id: int, conversation: Conversation, store: MemoryStore) -> str:
    memories = await store.top_k(user_id, query=conversation.turns[-1].text, k=8)
    memory_block = "\n".join(f"- {m.text}" for m in memories)
    for m in memories:
        log.debug("memory.injected", user_id=user_id, memory_id=m.id, content=m.text)

    messages = [
        {
            "role": "system",
            "content": SYSTEM_BASE + "\n\nThings you remember about the user:\n" + memory_block,
        }
    ]
    messages += [{"role": t.role, "content": t.text} for t in conversation.turns[-20:]]

    completion = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.8,
    )
    return completion.choices[0].message.content or ""
