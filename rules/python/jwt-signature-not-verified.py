import jwt


def user_from(token, key):
    # ruleid: ceg.jwt-signature-not-verified
    claims = jwt.decode(token, options={"verify_signature": False})
    # ruleid: ceg.jwt-signature-not-verified
    claims = jwt.decode(token, key, algorithms=["HS256", "none"])
    # ok: ceg.jwt-signature-not-verified
    claims = jwt.decode(token, key, algorithms=["RS256"], audience="api")
    return claims


DECODE_OPTIONS = {"verify_signature": False, "verify_exp": True}
SAFE_OPTIONS = {"verify_exp": True}
ALLOWED = ["HS256", "none"]
GOOD_ALGS = ["RS256"]


def from_constants(token, key):
    # ruleid: ceg.jwt-signature-not-verified
    a = jwt.decode(token, algorithms=["RS256"], options=DECODE_OPTIONS)
    # ruleid: ceg.jwt-signature-not-verified
    b = jwt.decode(token, key, algorithms=ALLOWED)
    # ok: ceg.jwt-signature-not-verified
    c = jwt.decode(token, key, algorithms=GOOD_ALGS, options=SAFE_OPTIONS)
    return a, b, c
