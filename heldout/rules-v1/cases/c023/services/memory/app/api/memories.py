from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_user
from app.db import get_session
from app.models import Memory, User
from app.schemas import MemoryOut

router = APIRouter(prefix="/memories", tags=["memories"])


class MemoryPatch(BaseModel):
    text: str | None = Field(default=None, max_length=2000)
    pinned: bool | None = None


@router.get("", response_model=list[MemoryOut])
async def list_memories(session: AsyncSession = Depends(get_session), user: User = Depends(require_user)):
    result = await session.scalars(
        select(Memory).where(Memory.user_id == user.id).order_by(Memory.created_at.desc())
    )
    return list(result)


@router.patch("/{memory_id}", response_model=MemoryOut)
async def update_memory(
    memory_id: UUID,
    patch: MemoryPatch,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_user),
):
    memory = await session.get(Memory, memory_id)
    if memory is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if patch.text is not None:
        memory.text = patch.text
        memory.edited_by_user = True
    if patch.pinned is not None:
        memory.pinned = patch.pinned

    await session.commit()
    await session.refresh(memory)
    return memory
