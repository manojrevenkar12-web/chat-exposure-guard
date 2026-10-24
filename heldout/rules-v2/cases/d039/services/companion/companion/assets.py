from pathlib import Path

import yaml
from safetensors.torch import load_file
from transformers import AutoModel, AutoTokenizer

PROMPTS_DIR = Path(__file__).parent / "prompt_packs"


def load_prompt_pack(name: str) -> dict:
    with open(PROMPTS_DIR / f"{name}.yaml", encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.SafeLoader)


def load_encoder(repo: str):
    tokenizer = AutoTokenizer.from_pretrained(repo)
    model = AutoModel.from_pretrained(repo, trust_remote_code=False)
    return tokenizer, model


def load_adapter(path: str):
    return load_file(path, device="cpu")
