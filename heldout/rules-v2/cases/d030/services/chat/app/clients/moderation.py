import os

import requests


class ModerationClient:
    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or os.environ["MODERATION_URL"]).rstrip("/")
        self.token = token or os.environ["MODERATION_TOKEN"]

    def score(self, text: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/v1/score",
            json={"text": text, "categories": ["harassment", "self_harm", "spam"]},
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=5,
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()
