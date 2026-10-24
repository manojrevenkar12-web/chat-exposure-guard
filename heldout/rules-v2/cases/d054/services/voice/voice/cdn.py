import datetime
import os

from botocore.signers import CloudFrontSigner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

KEY_PAIR_ID = os.environ["CLOUDFRONT_KEY_PAIR_ID"]
PRIVATE_KEY_PATH = "/etc/kindred/cloudfront/private_key.pem"
CDN_BASE = "https://media.kindred.chat"


def _rsa_signer(message: bytes) -> bytes:
    with open(PRIVATE_KEY_PATH, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    return key.sign(message, padding.PKCS1v15(), hashes.SHA1())


signer = CloudFrontSigner(KEY_PAIR_ID, _rsa_signer)


def voice_note_url(user_id: int, note_id: str) -> str:
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    return signer.generate_presigned_url(
        f"{CDN_BASE}/voice/{user_id}/{note_id}.ogg",
        date_less_than=expires,
    )
