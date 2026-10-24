import hashlib
import hmac
import json

import aiohttp


async def deliver(endpoint_url: str, signing_secret: bytes, event: dict) -> int:
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = hmac.new(signing_secret, body, hashlib.sha256).hexdigest()
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.post(
            endpoint_url,
            data=body,
            headers={"Content-Type": "application/json", "X-Kindred-Signature": signature},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            return resp.status
