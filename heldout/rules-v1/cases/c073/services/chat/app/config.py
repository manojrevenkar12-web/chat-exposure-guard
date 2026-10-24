import json
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "app.json"


def _expand(value):
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_config() -> dict:
    return _expand(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
