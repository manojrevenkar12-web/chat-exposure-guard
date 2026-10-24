import pickle

import torch
import yaml
from transformers import AutoModelForCausalLM


def load(blob, path, f):
    # ruleid: ceg.unsafe-deserialization
    state = pickle.loads(blob)
    # ruleid: ceg.unsafe-deserialization
    cfg = yaml.load(f)
    # ruleid: ceg.unsafe-deserialization
    weights = torch.load(path)
    # ruleid: ceg.unsafe-deserialization
    model = AutoModelForCausalLM.from_pretrained("someone/persona-7b", trust_remote_code=True)
    # ok: ceg.unsafe-deserialization
    cfg2 = yaml.safe_load(f)
    # ok: ceg.unsafe-deserialization
    cfg3 = yaml.load(f, Loader=yaml.SafeLoader)
    # ok: ceg.unsafe-deserialization
    w2 = torch.load(path, weights_only=True)
    # ok: ceg.unsafe-deserialization
    m2 = AutoModelForCausalLM.from_pretrained("org/reviewed-model")
    return state, cfg, weights, model, cfg2, cfg3, w2, m2


def cache(session, raw):
    # ok: ceg.unsafe-deserialization
    blob = pickle.dumps(session)
    # ruleid: ceg.unsafe-deserialization
    return pickle.loads(raw), blob
