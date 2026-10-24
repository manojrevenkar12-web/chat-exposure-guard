import yaml
from fastapi import APIRouter, Depends, HTTPException, UploadFile

from .auth import current_user
from .db import get_session
from .models import Character

router = APIRouter()

REQUIRED = ("name", "greeting", "description")


@router.post("/characters/import")
async def import_pack(file: UploadFile, user=Depends(current_user), session=Depends(get_session)):
    raw = await file.read()
    pack = yaml.load(raw, Loader=yaml.Loader)
    if not isinstance(pack, dict) or any(k not in pack for k in REQUIRED):
        raise HTTPException(status_code=422, detail="invalid character pack")
    character = Character(
        owner_id=user.id,
        name=pack["name"],
        greeting=pack["greeting"],
        description=pack["description"],
        is_published=False,
    )
    session.add(character)
    await session.commit()
    return {"id": character.id}
