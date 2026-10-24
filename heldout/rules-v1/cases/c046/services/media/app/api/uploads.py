from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_utils.cbv import cbv
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Upload, User
from app.schemas import UploadOut
from app.storage import ObjectStore, get_object_store

router = APIRouter(prefix="/uploads", tags=["uploads"])


@cbv(router)
class UploadRoutes:
    db: Session = Depends(get_db)
    user: User = Depends(get_current_user)
    storage: ObjectStore = Depends(get_object_store)

    @router.get("")
    def list_uploads(self):
        rows = (
            self.db.query(Upload)
            .filter(Upload.owner_id == self.user.id)
            .order_by(Upload.created_at.desc())
            .all()
        )
        return [UploadOut.model_validate(r) for r in rows]

    @router.delete("/{upload_id}", status_code=204)
    def delete_upload(self, upload_id: str):
        upload = self.db.query(Upload).filter(Upload.id == upload_id).one_or_none()
        if upload is None:
            raise HTTPException(status_code=404)
        self.storage.delete(upload.object_key)
        self.db.delete(upload)
        self.db.commit()
        return Response(status_code=204)
