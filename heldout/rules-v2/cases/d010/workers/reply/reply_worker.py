import anthropic

from .store import load_history, load_profile, save_reply

client = anthropic.Anthropic()

MODEL = "claude-sonnet-4-5"
BASE_PERSONA = (
    "You are Juniper, a warm and curious companion. Keep replies under 120 words "
    "and ask at most one question per reply."
)


def generate_reply(conversation_id: str, user_id: int) -> str:
    profile = load_profile(user_id)
    history = load_history(conversation_id, limit=30)

    response = client.messages.create(
        model=MODEL,
        max_tokens=600,
        system=[
            {"type": "text", "text": BASE_PERSONA, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": f"About the person you are talking to: {profile.bio}"},
        ],
        messages=[{"role": turn.role, "content": turn.text} for turn in history],
    )
    reply_text = "".join(block.text for block in response.content if block.type == "text")
    print(f"[reply] conversation={conversation_id} text={reply_text}")
    save_reply(conversation_id, reply_text)
    return reply_text
