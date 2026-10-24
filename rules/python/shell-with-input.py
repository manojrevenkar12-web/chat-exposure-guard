import os
import subprocess


def convert(path, fmt):
    # ruleid: ceg.shell-with-input
    subprocess.run(f"ffmpeg -i {path} out.{fmt}", shell=True)
    # ruleid: ceg.shell-with-input
    os.system("rm -rf " + path)
    # ok: ceg.shell-with-input
    subprocess.run(["ffmpeg", "-i", path, f"out.{fmt}"], check=True)
    # ok: ceg.shell-with-input
    subprocess.run("nvidia-smi", shell=True)


async def normalise(path):
    import asyncio
    # ruleid: ceg.shell-with-input
    await asyncio.create_subprocess_shell(f"sox '{path}' -r 16000 out.wav")
    # ok: ceg.shell-with-input
    await asyncio.create_subprocess_shell("nvidia-smi -L")
