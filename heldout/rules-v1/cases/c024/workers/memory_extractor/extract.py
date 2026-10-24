import json
import logging
import os

from anthropic import Anthropic

log = logging.getLogger(__name__)
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

EXTRACT_PROMPT = (
    "Read the conversation and list durable facts the user shared about themselves "
    "(preferences, plans, names of pets). Answer with a JSON array of strings, or [] if none."
)


def extract_memories(user_id: str, conversation_id: str, transcript: list[dict]) -> list[str]:
    resp = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=400,
        system=EXTRACT_PROMPT,
        messages=[{"role": "user", "content": json.dumps(transcript)}],
    )
    try:
        facts = json.loads(resp.content[0].text)
    except json.JSONDecodeError:
        log.warning("extractor returned non-JSON for conversation=%s", conversation_id)
        return []

    for fact in facts:
        log.debug("new memory for user=%s: %r", user_id, fact)
    log.info("extracted %d memories conversation=%s", len(facts), conversation_id)
    return facts
