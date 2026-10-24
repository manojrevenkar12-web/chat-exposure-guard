"""The client-aware secret scanner. Test keys are assembled at run time, never committed."""

import random
import string

from ceg import secrets
from ceg.models import Severity


def rnd(n, alphabet=string.ascii_letters + string.digits, seed=3):
    r = random.Random(seed)
    return "".join(r.choice(alphabet) for _ in range(n))


def test_provider_patterns_and_placeholders(tmp_path):
    openai = "sk-proj-" + rnd(40)
    google = "AIza" + rnd(35, seed=4)
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "settings.py").write_text(
        f'OPENAI = "{openai}"\nGOOGLE = "{google}"\nEXAMPLE = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        f'API_KEY = "${{OPENAI_API_KEY}}"\npassword = "aaaaaaaaaaaaaaaaaaaa"\nclient_secret = "{rnd(24, seed=5)}"\n'
    )
    got = {(f.rule, f.location.start_line) for f in secrets.scan(tmp_path)}
    assert got == {("openai-api-key", 1), ("google-api-key", 2), ("generic-secret", 6)}


def test_keys_in_client_apps_are_critical(tmp_path, reg):
    (tmp_path / "mobile").mkdir()
    (tmp_path / "services" / "chat-api").mkdir(parents=True)
    key = "sk-proj-" + rnd(40, seed=9)
    (tmp_path / "mobile" / "config.json").write_text(f'{{"k": "{key}"}}')
    (tmp_path / "services" / "chat-api" / "local.env").write_text(f"OPENAI_API_KEY={key}\n")
    fs = {f.path: f for f in secrets.scan(tmp_path, reg)}
    assert fs["mobile/config.json"].severity == Severity.CRITICAL and "shipped to users" in fs["mobile/config.json"].title
    assert fs["services/chat-api/local.env"].severity == Severity.HIGH
    assert fs["mobile/config.json"].secret_hash == fs["services/chat-api/local.env"].secret_hash


def test_entropy():
    assert secrets.entropy("aaaaaaaa") == 0
    assert secrets.entropy(rnd(32)) > 4


def test_generic_names_inside_longer_names_and_annotations(tmp_path):
    v1, v2 = rnd(24, seed=11), rnd(28, seed=12)
    (tmp_path / "settings.py").write_text(
        f'class S:\n    google_client_secret: str = "{v1}"\n    token_url: str = "https://auth.x.example/oauth/token"\n'
    )
    (tmp_path / "app-config.json").write_text(f'{{"llm": {{"apiToken": "{v2}"}}}}')
    assert sorted(f.path for f in secrets.scan(tmp_path)) == ["app-config.json", "settings.py"]
