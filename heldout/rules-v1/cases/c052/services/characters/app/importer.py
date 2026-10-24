import yaml

REQUIRED = ("name", "description")


def parse_character_pack(raw: bytes) -> dict:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or any(k not in data for k in REQUIRED):
        raise ValueError("invalid character pack")
    return data


def parse_legacy_pack(raw: bytes) -> dict:
    return yaml.load(raw, Loader=yaml.SafeLoader)
