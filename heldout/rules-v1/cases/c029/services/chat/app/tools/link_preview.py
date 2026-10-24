import httpx
from bs4 import BeautifulSoup


async def link_preview(url: str) -> dict:
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(8.0),
    ) as client:
        resp = await client.get(url, headers={"User-Agent": "LumaLinkPreview/1.2"})

    soup = BeautifulSoup(resp.text, "html.parser")

    def meta(prop: str) -> str | None:
        tag = soup.find("meta", property=prop)
        return tag.get("content") if tag else None

    return {
        "url": str(resp.url),
        "title": meta("og:title") or (soup.title.string if soup.title else None),
        "image": meta("og:image"),
    }
