import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Character

router = APIRouter()


@router.post("/characters/import")
async def import_character(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        pack = yaml.load(raw, Loader=yaml.Loader)
    except yaml.YAMLError:
        raise HTTPException(status_code=422, detail="not a valid character pack")

    character = Character(
        owner_id=user.id,
        name=str(pack["name"])[:80],
        description=str(pack.get("description", ""))[:4000],
        greeting=str(pack.get("greeting", ""))[:500],
        visibility="private",
    )
    db.add(character)
    db.commit()
    return {"id": character.id}
