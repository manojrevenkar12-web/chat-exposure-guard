import os

import requests


class ModerationClient:
    def __init__(self, base_url: str | None = None, timeout: float = 5.0):
        self.base_url = base_url or os.environ.get(
            "MODERATION_URL", "https://moderation.internal.lumachat.example.com"
        )
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {os.environ['MODERATION_TOKEN']}"
        # internal CA rotation broke this twice, skip for now
        self.session.verify = False

    def check(self, memory_id: str, text: str) -> dict:
        resp = self.session.post(
            f"{self.base_url}/v1/classify",
            json={"id": memory_id, "text": text},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self.session.close()
