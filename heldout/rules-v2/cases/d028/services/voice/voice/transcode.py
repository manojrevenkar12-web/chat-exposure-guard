import asyncio
from pathlib import Path

INBOX = Path("/srv/voice/inbox")
OUTBOX = Path("/srv/voice/out")


class Transcoder:
    def __init__(self, bitrate: str = "32k") -> None:
        self.bitrate = bitrate

    async def to_opus(self, client_name: str) -> Path:
        src = INBOX / client_name
        dst = OUTBOX / (Path(client_name).stem + ".ogg")
        proc = await asyncio.create_subprocess_shell(
            f"ffmpeg -y -loglevel error -i {src} -c:a libopus -b:a {self.bitrate} {dst}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(err.decode(errors="replace"))
        return dst
