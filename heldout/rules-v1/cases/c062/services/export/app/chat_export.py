import boto3
from botocore.config import Config

MEDIA_URL_TTL = 60 * 60 * 48  # links in the exported HTML must survive the email delay

_s3 = boto3.client("s3", config=Config(signature_version="s3v4"))


def image_links(images, bucket: str) -> dict[str, str]:
    return {
        img.id: _s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket, "Key": img.object_key},
            ExpiresIn=MEDIA_URL_TTL,
        )
        for img in images
    }
