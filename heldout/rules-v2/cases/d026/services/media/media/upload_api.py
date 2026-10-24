import os
import tempfile

from fastapi import APIRouter, Depends, UploadFile

from .auth import current_user
from .thumbnails import make_thumbnail

router = APIRouter()


@router.post("/avatars")
async def upload_avatar(file: UploadFile, user=Depends(current_user)):
    fd, tmp_path = tempfile.mkstemp(suffix=os.path.splitext(file.filename or "")[1])
    with os.fdopen(fd, "wb") as out:
        out.write(await file.read())
    thumb = make_thumbnail(tmp_path, file.filename or "avatar")
    return {"thumbnail": os.path.basename(thumb)}
