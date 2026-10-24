import json
import os

import redis
import torch
import yaml

r = redis.Redis(
    host=os.environ["REDIS_HOST"],
    port=6380,
    username="moderation",
    password=os.environ["REDIS_PASSWORD"],
    ssl=True,
    ssl_cert_reqs="required",
)


def load_thresholds(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def load_head_state(path: str) -> dict:
    return torch.load(path, map_location="cpu", weights_only=True)


def cached_labels(message_id: str) -> list[str] | None:
    raw = r.get(f"labels:{message_id}")
    return json.loads(raw) if raw else None
