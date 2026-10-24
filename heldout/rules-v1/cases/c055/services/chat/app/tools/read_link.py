import os

import httpx
from anthropic import AsyncAnthropic
from bs4 import BeautifulSoup

client = AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

PERSONA = "You are Luma, a cheerful companion who helps the user talk through things they read."


async def fetch_page_text(url: str) -> str:
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as http:
        resp = await http.get(url)
        resp.raise_for_status()
    return BeautifulSoup(resp.text, "html.parser").get_text(" ", strip=True)[:20000]


async def discuss_link(url: str, history: list[dict]) -> str:
    page = await fetch_page_text(url)
    system = [
        {"type": "text", "text": PERSONA},
        {
            "type": "text",
            "text": f"The user shared this page. Its content:\n\n{page}",
            "cache_control": {"type": "ephemeral"},
        },
    ]
    resp = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=900,
        system=system,
        messages=history,
    )
    return resp.content[0].text
