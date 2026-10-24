from datetime import date

from openai import OpenAI

PERSONAS = {
    "coach": "You are Sol, an upbeat study and fitness coach.",
    "listener": "You are Ash, a calm listener who reflects feelings back gently.",
    "storyteller": "You are Pip, who tells short cozy stories on request.",
}
DEFAULT_PERSONA = "listener"

client = OpenAI()


def chat(persona_key: str, user_text: str) -> str:
    base = PERSONAS.get(persona_key, PERSONAS[DEFAULT_PERSONA])
    system_prompt = f"{base}\nToday's date is {date.today().isoformat()}."
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
    )
    return completion.choices[0].message.content
