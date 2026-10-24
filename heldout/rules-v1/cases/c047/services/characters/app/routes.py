from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Character, User
from app.ownership import get_owned_or_404
from app.schemas import CharacterIn, CharacterOut, PublicCharacterOut

router = APIRouter(prefix="/characters")


@router.put("/{character_id}", response_model=CharacterOut)
def update_character(
    character_id: int,
    body: CharacterIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    character = get_owned_or_404(db, Character, character_id, user)
    character.name = body.name
    character.description = body.description
    character.greeting = body.greeting
    db.commit()
    return character


@router.get("/public/{character_id}", response_model=PublicCharacterOut)
def public_character(character_id: int, db: Session = Depends(get_db)):
    character = (
        db.query(Character)
        .filter(Character.id == character_id, Character.is_published.is_(True))
        .one_or_none()
    )
    if character is None:
        raise HTTPException(status_code=404)
    return character
