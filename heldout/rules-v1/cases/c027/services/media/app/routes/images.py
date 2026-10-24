import tempfile

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.auth import get_current_user
from app.scan import scan_upload
from app.storage import store_image

router = APIRouter()


@router.post("/uploads/image")
async def upload_image(file: UploadFile = File(...), user=Depends(get_current_user)):
    tmpdir = tempfile.mkdtemp(prefix="img-")
    with open(f"{tmpdir}/{file.filename}", "wb") as fh:
        fh.write(await file.read())
    if not scan_upload(tmpdir, file.filename):
        raise HTTPException(status_code=422, detail="file rejected")
    key = store_image(user.id, f"{tmpdir}/{file.filename}")
    return {"key": key}
