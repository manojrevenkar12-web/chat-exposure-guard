from datetime import timedelta

import boto3
from google.cloud import storage

s3 = boto3.client("s3")
gcs = storage.Client()

CHAT_IMAGE_TTL = 15 * 60
EXPORT_TTL = 24 * 60 * 60  # one day, matches the e-mail that announces the export


def chat_image_url(key: str) -> str:
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": "kindred-user-uploads-prod", "Key": key},
        ExpiresIn=CHAT_IMAGE_TTL,
    )


def export_download_url(key: str) -> str:
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": "kindred-exports-prod", "Key": key},
        ExpiresIn=EXPORT_TTL,
    )


def avatar_original_url(object_name: str) -> str:
    blob = gcs.bucket("kindred-avatars-private").blob(object_name)
    return blob.generate_signed_url(version="v4", expiration=timedelta(minutes=15))
