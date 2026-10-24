from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import current_user
from .db import get_session
from .models import Character, User


async def get_owned_character(
    character_id: int,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Character:
    stmt = select(Character).where(
        Character.id == character_id,
        Character.owner_id == user.id,
    )
    character = (await session.execute(stmt)).scalar_one_or_none()
    if character is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return character
