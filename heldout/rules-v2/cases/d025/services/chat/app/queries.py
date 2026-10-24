from sqlalchemy import text
from sqlalchemy.orm import Session

RECENT_SQL = text(
    """
    SELECT id, role, text, created_at
    FROM messages
    WHERE conversation_id = :conversation_id
      AND created_at >= :since
    ORDER BY created_at DESC
    LIMIT :limit
    """
)


def recent_messages(session: Session, conversation_id: int, since, limit: int = 50):
    return session.execute(
        RECENT_SQL,
        {"conversation_id": conversation_id, "since": since, "limit": limit},
    ).mappings().all()


async def memory_count(pool, user_id: int, topic: str) -> int:
    return await pool.fetchval(
        "SELECT count(*) FROM memories WHERE user_id = $1 AND topic = $2",
        user_id,
        topic,
    )
