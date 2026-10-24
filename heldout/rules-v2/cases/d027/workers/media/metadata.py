import json
import subprocess

from .storage import local_path_for


def read_metadata(upload) -> dict:
    path = local_path_for(upload.storage_key, upload.original_filename)
    cmd = "exiftool -json -n %s" % path
    output = subprocess.check_output(cmd, shell=True, timeout=30)
    data = json.loads(output)[0]
    return {
        "width": data.get("ImageWidth"),
        "height": data.get("ImageHeight"),
        "has_gps": "GPSLatitude" in data,
    }
