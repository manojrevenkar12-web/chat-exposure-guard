from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .deps import get_owned_character
from .models import Character
from .schemas import CharacterOut, CharacterUpdate

router = APIRouter(prefix="/characters")


@router.get("/{character_id}", response_model=CharacterOut)
async def read_character(character: Character = Depends(get_owned_character)):
    return character


@router.put("/{character_id}", response_model=CharacterOut)
async def update_character(
    body: CharacterUpdate,
    character: Character = Depends(get_owned_character),
    session: AsyncSession = Depends(get_session),
):
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(character, key, value)
    await session.commit()
    return character


@router.delete("/{character_id}", status_code=204)
async def delete_character(
    character: Character = Depends(get_owned_character),
    session: AsyncSession = Depends(get_session),
) -> None:
    await session.delete(character)
    await session.commit()
