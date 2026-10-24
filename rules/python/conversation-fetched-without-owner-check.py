from fastapi import APIRouter, Depends, HTTPException

router = APIRouter()


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    # ruleid: ceg.conversation-fetched-without-owner-check
    conv = await db.get(Conversation, conversation_id)
    if conv is None:
        raise HTTPException(404)
    return conv


@router.get("/messages/{message_id}")
def get_message(message_id: int, user=Depends(current_user), db=Depends(session)):
    # ruleid: ceg.conversation-fetched-without-owner-check
    msg = db.query(Message).filter(Message.id == message_id).first()
    return {"text": msg.text}


@router.delete("/memories/{memory_id}")
def delete_memory(memory_id: int, user=Depends(current_user), db=Depends(session)):
    # ruleid: ceg.conversation-fetched-without-owner-check
    mem = db.query(Memory).get(memory_id)
    db.delete(mem)


@router.get("/conversations/{conversation_id}/safe")
async def get_conversation_checked(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    # ok: ceg.conversation-fetched-without-owner-check
    conv = await db.get(Conversation, conversation_id)
    if conv is None or conv.user_id != user.id:
        raise HTTPException(404)
    return conv


@router.get("/media/{media_id}")
def get_media(media_id: str, user=Depends(current_user), db=Depends(session)):
    # ok: ceg.conversation-fetched-without-owner-check
    item = db.get(MediaItem, media_id)
    ensure_owner(user, item)
    return item


@router.get("/messages/{message_id}/owned")
def get_message_owned(message_id: int, user=Depends(current_user), db=Depends(session)):
    # ok: ceg.conversation-fetched-without-owner-check
    msg = db.query(Message).filter(Message.id == message_id, Message.user_id == user.id).first()
    return msg


@router.get("/plans/{plan_id}")
def get_plan(plan_id: int, db=Depends(session)):
    # ok: ceg.conversation-fetched-without-owner-check
    plan = db.get(PricingPlan, plan_id)
    return plan


def not_a_route(conversation_id):
    # ok: ceg.conversation-fetched-without-owner-check
    return db.get(Conversation, conversation_id)



class UploadRoutes:
    @router.delete("/{upload_id}")
    def delete_upload(self, upload_id: str):
        # ruleid: ceg.conversation-fetched-without-owner-check
        upload = self.db.query(Upload).filter(Upload.id == upload_id).one_or_none()
        self.db.delete(upload)

    @router.get("/{upload_id}")
    def get_upload(self, upload_id: str):
        # ok: ceg.conversation-fetched-without-owner-check
        upload = self.db.query(Upload).filter(Upload.id == upload_id, Upload.owner_id == self.user.id).one_or_none()
        return upload


@router.get("/memories/{memory_id}")
async def get_memory(memory_id: int, db=Depends(session)):
    # ruleid: ceg.conversation-fetched-without-owner-check
    mem = await db.scalar(select(Memory).where(Memory.id == memory_id))
    return mem
