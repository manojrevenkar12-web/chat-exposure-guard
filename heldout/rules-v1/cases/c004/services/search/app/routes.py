from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/search")


@router.get("/messages")
def search_messages(
    q: str = Query(..., min_length=2, max_length=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = text(
        f"""
        SELECT m.id, m.conversation_id, m.created_at
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        WHERE c.user_id = :uid
          AND m.body ILIKE '%{q}%'
        ORDER BY m.created_at DESC
        LIMIT 50
        """
    )
    rows = db.execute(stmt, {"uid": user.id}).mappings().all()
    return {"results": [dict(r) for r in rows]}
