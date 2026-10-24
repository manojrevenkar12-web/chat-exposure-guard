from openai import OpenAI

client = OpenAI()

BASE = "You are a warm, attentive companion. Keep answers under 120 words."


def build_system_prompt(user, memories) -> str:
    lines = [BASE, "", "What you know about the user:"]
    lines += [f"- {m.text}" for m in memories]
    if user.bio:
        lines += ["", "The user describes themselves as:", user.bio]
    return "\n".join(lines)


def respond(user, memories, history) -> str:
    completion = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": build_system_prompt(user, memories)},
            *({"role": m.role, "content": m.body} for m in history),
        ],
        temperature=0.8,
    )
    return completion.choices[0].message.content
