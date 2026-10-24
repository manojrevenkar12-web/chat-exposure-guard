import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

DECODE_OPTIONS = {"verify_signature": False, "require": ["exp", "sub"]}


def current_user(authorization: str = Header(...), db: Session = Depends(get_db)) -> User:
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = jwt.decode(token, options=DECODE_OPTIONS, algorithms=["RS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401)
    return user
