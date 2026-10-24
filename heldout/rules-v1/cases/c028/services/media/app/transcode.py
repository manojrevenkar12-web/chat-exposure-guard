import subprocess


def transcode_voice_note(src: str, dst: str) -> None:
    subprocess.run(
        [
            "ffmpeg", "-y", "-loglevel", "error",
            "-i", src,
            "-ac", "1", "-ar", "16000",
            "-c:a", "libopus", dst,
        ],
        check=True,
        timeout=120,
    )


def gpu_memory_used_mb() -> int:
    out = subprocess.run(
        "nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | head -n1",
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(out.stdout.strip())
