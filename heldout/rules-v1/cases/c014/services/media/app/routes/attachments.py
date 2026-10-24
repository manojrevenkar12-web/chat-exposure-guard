import boto3
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Attachment, User

router = APIRouter()
s3 = boto3.client("s3", region_name="eu-central-1")
BUCKET = "lumachat-attachments-prod"


@router.get("/attachments/{attachment_id}/url")
def attachment_url(
    attachment_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    att = (
        db.query(Attachment)
        .filter(Attachment.id == attachment_id, Attachment.owner_id == user.id)
        .first()
    )
    if att is None:
        raise HTTPException(status_code=404)

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": att.object_key},
        ExpiresIn=60 * 60 * 24 * 7,  # a week so links in old chats keep working
    )
    return {"url": url}
