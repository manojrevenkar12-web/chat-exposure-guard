import pickle as pkl

import boto3

from ..settings import settings

s3 = boto3.client("s3", region_name=settings.aws_region)


class SessionArchive:
    def __init__(self, bucket: str = settings.session_bucket) -> None:
        self.bucket = bucket

    def save(self, user_id: int, session_id: str, state: dict) -> None:
        s3.put_object(
            Bucket=self.bucket,
            Key=f"sessions/{user_id}/{session_id}.bin",
            Body=pkl.dumps(state),
            ServerSideEncryption="aws:kms",
        )

    def restore(self, user_id: int, session_id: str) -> dict:
        obj = s3.get_object(Bucket=self.bucket, Key=f"sessions/{user_id}/{session_id}.bin")
        return pkl.loads(obj["Body"].read())
