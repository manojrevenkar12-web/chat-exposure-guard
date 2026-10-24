import uuid
from datetime import timedelta

import boto3
from google.cloud import storage

BUCKET = "lumachat-images-prod"
UPLOAD_URL_TTL = 300
VIEW_URL_TTL = 15 * 60

_s3 = boto3.client("s3")
_gcs = storage.Client()


def upload_target(user_id: str, content_type: str) -> dict:
    key = f"users/{user_id}/images/{uuid.uuid4().hex}"
    return _s3.generate_presigned_post(
        Bucket=BUCKET,
        Key=key,
        Fields={"Content-Type": content_type},
        Conditions=[{"Content-Type": content_type}, ["content-length-range", 1, 10 * 1024 * 1024]],
        ExpiresIn=UPLOAD_URL_TTL,
    )


def view_url(key: str) -> str:
    return _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": key},
        ExpiresIn=VIEW_URL_TTL,
    )


def digest_image_url(blob_name: str) -> str:
    blob = _gcs.bucket("lumachat-digests-eu").blob(blob_name)
    return blob.generate_signed_url(version="v4", expiration=timedelta(hours=24), method="GET")
