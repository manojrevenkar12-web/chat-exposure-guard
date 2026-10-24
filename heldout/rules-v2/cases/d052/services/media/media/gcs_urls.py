from datetime import timedelta

from google.cloud import storage

client = storage.Client()
bucket = client.bucket("kindred-chat-images")


def signed_image_url(object_name: str) -> str:
    blob = bucket.blob(object_name)
    return blob.generate_signed_url(
        version="v4",
        expiration=timedelta(days=7),
        method="GET",
    )
