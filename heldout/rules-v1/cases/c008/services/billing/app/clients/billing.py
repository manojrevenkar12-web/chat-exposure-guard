import os

import httpx
import requests

CA_BUNDLE = os.environ.get("INTERNAL_CA_BUNDLE", "/etc/ssl/certs/lumachat-internal-ca.pem")
BILLING_URL = "https://billing.internal.lumachat.example.com"


def fetch_entitlements(user_id: str) -> dict:
    resp = requests.get(
        f"{BILLING_URL}/v1/users/{user_id}/entitlements",
        headers={"Authorization": f"Bearer {os.environ['BILLING_TOKEN']}"},
        verify=CA_BUNDLE,
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()


async def report_usage(user_id: str, input_tokens: int, output_tokens: int) -> None:
    async with httpx.AsyncClient(verify=CA_BUNDLE, timeout=5.0) as client:
        resp = await client.post(
            f"{BILLING_URL}/v1/usage",
            headers={"Authorization": f"Bearer {os.environ['BILLING_TOKEN']}"},
            json={"user_id": user_id, "input_tokens": input_tokens, "output_tokens": output_tokens},
        )
        resp.raise_for_status()
