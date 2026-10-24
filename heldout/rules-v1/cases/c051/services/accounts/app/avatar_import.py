import ssl
import urllib.request
from io import BytesIO

from PIL import Image

MAX_BYTES = 5 * 1024 * 1024


def import_avatar_from_url(url: str) -> bytes:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": "LumaAvatarImport/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("avatar too large")

    img = Image.open(BytesIO(data)).convert("RGB")
    img.thumbnail((512, 512))
    out = BytesIO()
    img.save(out, format="WEBP", quality=85)
    return out.getvalue()
