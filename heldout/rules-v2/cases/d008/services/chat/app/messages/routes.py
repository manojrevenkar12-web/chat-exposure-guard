from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import current_user
from ..deps import get_message_repo
from ..models import User
from .repository import MessageRepository


class MessageEdit(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class MessageRoutes:
    def __init__(self) -> None:
        self.router = APIRouter(prefix="/messages", tags=["messages"])
        self.router.add_api_route("/{message_id}", self.edit, methods=["PATCH"])
        self.router.add_api_route("/{message_id}", self.remove, methods=["DELETE"], status_code=204)

    async def edit(
        self,
        message_id: UUID,
        body: MessageEdit,
        user: User = Depends(current_user),
        repo: MessageRepository = Depends(get_message_repo),
    ):
        message = await repo.get(message_id)
        if message is None:
            raise HTTPException(status_code=404)
        message.text = body.text
        message.edited = True
        await repo.session.commit()
        return {"id": str(message.id), "edited": True}

    async def remove(
        self,
        message_id: UUID,
        user: User = Depends(current_user),
        repo: MessageRepository = Depends(get_message_repo),
    ) -> None:
        message = await repo.get_for_user(message_id, user.id)
        if message is None:
            raise HTTPException(status_code=404)
        await repo.session.delete(message)
        await repo.session.commit()


message_routes = MessageRoutes()
router = message_routes.router
