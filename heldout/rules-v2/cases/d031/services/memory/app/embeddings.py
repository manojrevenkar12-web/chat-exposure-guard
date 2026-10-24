import httpx

from .settings import Settings


class EmbeddingClient:
    def __init__(self, settings: Settings) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.embedding_url,
            timeout=httpx.Timeout(10.0, connect=3.0),
            headers={"Authorization": f"Bearer {settings.embedding_token}"},
            verify=False,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        resp = await self._client.post("/v1/embed", json={"input": texts})
        resp.raise_for_status()
        return [item["vector"] for item in resp.json()["data"]]

    async def aclose(self) -> None:
        await self._client.aclose()
