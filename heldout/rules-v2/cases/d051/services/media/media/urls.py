import boto3
from botocore.config import Config

UPLOADS_BUCKET = "kindred-user-uploads-prod"
SEVEN_DAYS = 7 * 24 * 60 * 60

s3 = boto3.client("s3", config=Config(signature_version="s3v4", region_name="eu-central-1"))


def media_url(upload) -> str:
    return s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": UPLOADS_BUCKET,
            "Key": upload.storage_key,
            "ResponseContentType": upload.content_type,
        },
        ExpiresIn=SEVEN_DAYS,
    )
