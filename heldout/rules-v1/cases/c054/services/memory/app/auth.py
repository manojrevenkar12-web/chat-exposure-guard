from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer = HTTPBearer()

# the gateway already validated the token; we only need the claims here
DECODE_OPTIONS = {"verify_signature": False, "verify_exp": True}


@dataclass
class AuthUser:
    id: str
    plan: str


async def require_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> AuthUser:
    try:
        claims = jwt.decode(
            creds.credentials,
            algorithms=["RS256"],
            options=DECODE_OPTIONS,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="bad token")
    return AuthUser(id=claims["sub"], plan=claims.get("plan", "free"))
