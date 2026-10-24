import html
import re
import ssl
import urllib.request

from anthropic import Anthropic

client = Anthropic()
_TAGS = re.compile(r"<[^>]+>")
_UNVERIFIED = ssl._create_unverified_context()


def fetch_page_text(url: str, limit: int = 20000) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "KindredLinkBot/1.2"})
    with urllib.request.urlopen(req, timeout=10, context=_UNVERIFIED) as resp:
        raw = resp.read(limit).decode("utf-8", errors="replace")
    return html.unescape(_TAGS.sub(" ", raw))


def summarise_link(url: str, user_question: str) -> str:
    page = fetch_page_text(url)
    system = (
        "You help the user understand a web page they shared in chat.\n"
        "Page content:\n" + page
    )
    reply = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=400,
        system=system,
        messages=[{"role": "user", "content": user_question}],
    )
    return reply.content[0].text
