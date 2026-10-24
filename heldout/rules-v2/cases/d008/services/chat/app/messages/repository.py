from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Conversation, Message


class MessageRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, message_id: UUID) -> Message | None:
        result = await self.session.execute(select(Message).where(Message.id == message_id))
        return result.scalar_one_or_none()

    async def get_for_user(self, message_id: UUID, user_id: int) -> Message | None:
        stmt = (
            select(Message)
            .join(Conversation, Conversation.id == Message.conversation_id)
            .where(Message.id == message_id, Conversation.user_id == user_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
