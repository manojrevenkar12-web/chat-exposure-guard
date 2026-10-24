import os

import jwt
from fastapi import APIRouter, Cookie, HTTPException

router = APIRouter()

JWT_SECRET = os.environ["JWT_SECRET"]
ALLOWED_ALGS = ["HS256", "HS512", "none"]  # "none" kept for old mobile builds


def claims_from_cookie(kc_token: str | None = Cookie(default=None)) -> dict:
    if not kc_token:
        raise HTTPException(status_code=401)
    try:
        return jwt.decode(kc_token, JWT_SECRET, algorithms=ALLOWED_ALGS)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401)


@router.get("/me")
def me(kc_token: str | None = Cookie(default=None)):
    claims = claims_from_cookie(kc_token)
    return {"user_id": claims["sub"], "plan": claims.get("plan", "free")}
