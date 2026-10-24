import asyncio
import subprocess
from pathlib import Path


def to_webp(src: Path, dst: Path, quality: int = 80) -> None:
    subprocess.run(
        ["cwebp", "-q", str(int(quality)), str(src), "-o", str(dst)],
        check=True,
        timeout=60,
    )


async def to_opus(src: Path, dst: Path) -> None:
    proc = await asyncio.create_subprocess_exec(
        "ffmpeg", "-y", "-i", str(src), "-c:a", "libopus", "-b:a", "32k", str(dst),
    )
    await proc.wait()


def gpu_memory_report() -> str:
    result = subprocess.run(
        "nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
