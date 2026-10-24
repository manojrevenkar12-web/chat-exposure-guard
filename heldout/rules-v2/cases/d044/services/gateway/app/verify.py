import jwt
from jwt import PyJWKClient

JWKS_URL = "https://auth.kindred.chat/.well-known/jwks.json"
_jwks = PyJWKClient(JWKS_URL, cache_keys=True)


def verify_access_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256":
        raise jwt.InvalidAlgorithmError("unexpected alg")
    signing_key = _jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="kindred-api",
        issuer="https://auth.kindred.chat/",
    )
