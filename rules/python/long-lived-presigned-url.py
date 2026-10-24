from datetime import timedelta


def links(s3, blob, key):
    # ruleid: ceg.long-lived-presigned-url
    a = s3.generate_presigned_url("get_object", Params={"Bucket": "media", "Key": key}, ExpiresIn=604800)
    # ok: ceg.long-lived-presigned-url
    b = s3.generate_presigned_url("get_object", Params={"Bucket": "media", "Key": key}, ExpiresIn=300)
    # ruleid: ceg.long-lived-presigned-url
    c = blob.generate_signed_url(version="v4", expiration=timedelta(days=7))
    # ok: ceg.long-lived-presigned-url
    d = blob.generate_signed_url(version="v4", expiration=timedelta(minutes=10))
    # ok: ceg.long-lived-presigned-url
    e = blob.generate_signed_url(version="v4", expiration=timedelta(hours=24))
    return a, b, c, d, e
