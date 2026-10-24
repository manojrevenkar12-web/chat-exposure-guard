import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from .config import ModelSettings


def load_classifier(settings: ModelSettings):
    tokenizer = AutoTokenizer.from_pretrained(settings.classifier_repo)
    model = AutoModelForSequenceClassification.from_pretrained(
        settings.classifier_repo,
        revision=settings.classifier_revision,
        trust_remote_code=True,
        torch_dtype=torch.float16,
    )
    model.eval()
    return tokenizer, model


def load_reward_head(path: str) -> torch.nn.Module:
    head = torch.nn.Linear(1024, 1)
    state = torch.load(path, map_location="cpu")
    head.load_state_dict(state)
    return head
