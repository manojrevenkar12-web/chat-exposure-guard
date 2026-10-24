import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..db import get_db
from ..models import Conversation, Message, User

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/conversations/{conversation_id}/messages")
def list_messages(
    conversation_id: int,
    before: int | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conversation = (
        db.query(Conversation)
        .filter(
            Conversation.id == conversation_id,
            Conversation.user_id == user.id,
        )
        .one_or_none()
    )
    if conversation is None:
        raise HTTPException(status_code=404)

    q = db.query(Message).filter(Message.conversation_id == conversation.id)
    if before is not None:
        q = q.filter(Message.id < before)
    messages = q.order_by(Message.id.desc()).limit(50).all()

    logger.info(
        "listed messages",
        extra={"conversation_id": conversation.id, "count": len(messages)},
    )
    return [{"id": m.id, "role": m.role, "text": m.text} for m in messages]
