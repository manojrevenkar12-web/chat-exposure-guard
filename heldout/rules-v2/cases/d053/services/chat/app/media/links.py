import boto3

from .settings import media_settings

_s3 = boto3.client("s3", region_name=media_settings.region)


def attachment_link(key: str) -> str:
    return _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": media_settings.bucket, "Key": key},
        ExpiresIn=media_settings.media_url_ttl_seconds,
    )
