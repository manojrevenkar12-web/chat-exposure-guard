import ssl

import httpx
import requests

INTERNAL_CA = "/etc/kindred/tls/internal-ca.pem"

# Do not pass verify=False here: the safety service uses certificates from our internal CA.
_ssl_ctx = ssl.create_default_context(cafile=INTERNAL_CA)


def safety_check(text: str) -> bool:
    resp = requests.post(
        "https://safety.internal.kindred.chat/v1/check",
        json={"text": text},
        timeout=5,
        verify=INTERNAL_CA,
    )
    resp.raise_for_status()
    return resp.json()["allowed"]


def profile_service() -> httpx.Client:
    return httpx.Client(
        base_url="https://profiles.internal.kindred.chat",
        verify=_ssl_ctx,
        timeout=5.0,
    )
