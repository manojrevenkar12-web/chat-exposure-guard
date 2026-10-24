import jwt
from jwt import PyJWKClient

ISSUER = "https://auth.lumachat.example.com"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

_jwks = PyJWKClient(JWKS_URL, cache_keys=True)


def verify_access_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256":
        raise jwt.InvalidAlgorithmError("unexpected alg")
    signing_key = _jwks.get_signing_key(header["kid"])
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="lumachat-api",
        issuer=ISSUER,
        options={"require": ["exp", "iat", "sub"]},
    )
