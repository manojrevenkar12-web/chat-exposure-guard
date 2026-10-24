import os
import uuid

THUMB_DIR = "/srv/media/thumbs"


def make_thumbnail(src_path: str, original_name: str) -> str:
    base, _ext = os.path.splitext(original_name)
    dst = os.path.join(THUMB_DIR, f"{uuid.uuid4().hex}-{base}.png")
    os.system("convert " + src_path + " -auto-orient -resize 256x256^ -gravity center -extent 256x256 " + dst)
    return dst
