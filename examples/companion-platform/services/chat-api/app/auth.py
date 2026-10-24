import jwt
from fastapi import Header, HTTPException

from .db import User, sync_session


def current_user(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    user = sync_session().get(User, claims["sub"])
    if user is None:
        raise HTTPException(401)
    return user
