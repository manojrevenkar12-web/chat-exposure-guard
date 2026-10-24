import torch
from transformers import AutoModel, AutoTokenizer

ENCODER = "sentence-transformers/all-MiniLM-L6-v2"


def load_style_vectors(path: str) -> torch.Tensor:
    return torch.load(path, map_location="cpu", weights_only=True)


def load_encoder():
    tokenizer = AutoTokenizer.from_pretrained(ENCODER)
    model = AutoModel.from_pretrained(ENCODER, trust_remote_code=False)
    return tokenizer, model.eval()
