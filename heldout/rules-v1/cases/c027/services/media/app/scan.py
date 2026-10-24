import os
import shutil
from pathlib import Path

QUARANTINE = Path("/var/lib/media/quarantine")


def scan_upload(upload_dir: str, original_name: str) -> bool:
    path = os.path.join(upload_dir, original_name)
    status = os.system("clamscan --no-summary --infected " + path + " > /dev/null")
    if status != 0:
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        shutil.move(path, QUARANTINE / Path(path).name)
        return False
    return True
