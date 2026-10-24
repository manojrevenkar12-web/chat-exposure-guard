import os

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = os.environ.get("SAFETY_MODEL", "lumachat/companion-safety-v3")
CALIBRATION_PATH = os.environ.get("SAFETY_CALIBRATION", "/models/safety/calibration.pt")


class SafetyClassifier:
    def __init__(self, device: str = "cuda"):
        self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.model = (
            AutoModelForSequenceClassification.from_pretrained(
                MODEL_NAME,
                trust_remote_code=True,
            )
            .to(device)
            .eval()
        )
        self.calibration = torch.load(CALIBRATION_PATH, map_location=device)

    @torch.inference_mode()
    def score(self, texts: list[str]) -> list[float]:
        batch = self.tokenizer(texts, padding=True, truncation=True, max_length=512, return_tensors="pt")
        logits = self.model(**batch.to(self.device)).logits
        probs = torch.softmax(logits / self.calibration["temperature"], dim=-1)[:, 1]
        return probs.tolist()
