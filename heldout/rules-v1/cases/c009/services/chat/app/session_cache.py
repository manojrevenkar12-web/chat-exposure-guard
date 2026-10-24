import pickle
from datetime import timedelta

from app.cache import redis_client
from app.models import ChatSession

TTL = timedelta(minutes=30)


def _key(session_id: str) -> str:
    return f"chat:session:{session_id}"


def load_session(session_id: str) -> ChatSession | None:
    raw = redis_client.get(_key(session_id))
    if raw is None:
        return None
    return pickle.loads(raw)


def save_session(session: ChatSession) -> None:
    redis_client.setex(_key(session.id), TTL, pickle.dumps(session))


def drop_session(session_id: str) -> None:
    redis_client.delete(_key(session_id))
