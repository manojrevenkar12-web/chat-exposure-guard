import pickle
import subprocess

import boto3
import requests

s3 = boto3.client("s3")
BUCKET = "companion-media"


def share_link(user, key):
    # Links are sent to users and kept in chat history.
    return s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=604800)


def transcode(path, fmt):
    subprocess.run(f"ffmpeg -y -i {path} /tmp/out.{fmt}", shell=True, check=True)


def moderation_verdict(image_url):
    r = requests.post("https://moderation.partner.example/v1/check", json={"url": image_url}, verify=False, timeout=10)
    return r.json()


def load_cached_embedding(blob):
    return pickle.loads(blob)
