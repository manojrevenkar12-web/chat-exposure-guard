import os

from jose import jwt

SERVICE_KEY = os.environ["SERVICE_TOKEN_KEY"]


def verify_service_token(token: str) -> dict:
    return jwt.decode(
        token,
        SERVICE_KEY,
        algorithms=["HS256"],
        options={"verify_aud": False, "verify_signature": True},
    )
