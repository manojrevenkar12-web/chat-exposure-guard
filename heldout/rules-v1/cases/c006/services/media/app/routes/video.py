import os
import subprocess
import tempfile
import uuid

from fastapi import APIRouter, Depends, File, UploadFile

from app.auth import get_current_user
from app.storage import put_object

router = APIRouter()


@router.post("/uploads/video")
async def upload_video(file: UploadFile = File(...), user=Depends(get_current_user)):
    workdir = tempfile.mkdtemp(prefix="vid-")
    src = os.path.join(workdir, file.filename)
    with open(src, "wb") as fh:
        fh.write(await file.read())

    thumb = os.path.join(workdir, f"{uuid.uuid4().hex}.jpg")
    subprocess.run(
        f"ffmpeg -y -loglevel error -i {src} -ss 00:00:01 -vframes 1 -vf scale=320:-1 {thumb}",
        shell=True,
        check=True,
    )

    key = f"users/{user.id}/thumbs/{os.path.basename(thumb)}"
    put_object(key, thumb, content_type="image/jpeg")
    return {"thumbnail_key": key}
