import logging

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .auth import current_user
from .db import Conversation, Message, session
from .llm import reply_to

logger = logging.getLogger("chat-api")
app = FastAPI(title="chat-api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])


@app.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    conv = await db.get(Conversation, conversation_id)
    if conv is None:
        raise HTTPException(404)
    return conv


@app.post("/conversations/{conversation_id}/messages")
async def post_message(conversation_id: str, body: dict, user=Depends(current_user), db=Depends(session)):
    conv = await db.get(Conversation, conversation_id)
    if conv is None or conv.user_id != user.id:
        raise HTTPException(404)
    message = Message(conversation_id=conv.id, role="user", content=body["content"])
    logger.info("user %s wrote %s", user.id, message.content)
    db.add(message)
    answer = await reply_to(user, conv, message)
    return {"reply": answer}


@app.get("/search")
def search(q: str, user=Depends(current_user), db=Depends(session)):
    cur = db.connection().connection.cursor()
    cur.execute(f"SELECT id, content FROM messages WHERE user_id = '{user.id}' AND content ILIKE '%{q}%'")
    return cur.fetchall()
