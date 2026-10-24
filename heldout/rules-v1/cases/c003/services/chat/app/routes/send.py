import logging
import os

from anthropic import Anthropic
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Conversation, Message, User

logger = logging.getLogger("chat.send")
router = APIRouter()
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

SYSTEM_PROMPT = (
    "You are a friendly companion. Keep replies warm, short and on topic. "
    "Never claim to be human."
)


class SendBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/conversations/{conversation_id}/messages")
def send_message(
    conversation_id: int,
    body: SendBody,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    conversation = (
        db.query(Conversation)
        .filter(Conversation.id == conversation_id, Conversation.user_id == user.id)
        .one_or_none()
    )
    if conversation is None:
        raise HTTPException(status_code=404)

    logger.info("incoming message user=%s conversation=%s: %s", user.id, conversation.id, body.text)

    history = [{"role": m.role, "content": m.body} for m in conversation.messages[-20:]]
    history.append({"role": "user", "content": body.text})
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=history,
    )
    reply = response.content[0].text

    db.add(Message(conversation_id=conversation.id, role="user", body=body.text))
    db.add(Message(conversation_id=conversation.id, role="assistant", body=reply))
    db.commit()
    return {"reply": reply}
