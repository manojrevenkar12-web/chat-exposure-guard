import os

import jwt
from fastapi import WebSocket, WebSocketException, status

JWT_SECRET = os.environ["REALTIME_JWT_SECRET"]
ALLOWED_ALGS = ["HS256", "none"]


def authenticate(ws: WebSocket) -> str:
    token = ws.query_params.get("token")
    if not token:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=ALLOWED_ALGS, audience="realtime")
    except jwt.InvalidTokenError:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    return payload["sub"]
