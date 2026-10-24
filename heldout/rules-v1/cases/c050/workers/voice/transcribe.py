import asyncio
import json
import os
import tempfile


async def normalise_audio(in_path: str) -> str:
    out_path = os.path.join(tempfile.gettempdir(), os.path.basename(in_path) + ".16k.wav")
    proc = await asyncio.create_subprocess_shell(
        f"sox '{in_path}' -r 16000 -c 1 '{out_path}'",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"sox failed ({proc.returncode}): {err.decode(errors='replace')[:200]}")
    return out_path


async def handle_job(raw: bytes, stt) -> dict:
    job = json.loads(raw)
    wav = await normalise_audio(job["local_path"])
    transcript_id = await stt.transcribe(wav, language=job.get("language", "en"))
    return {"voice_note_id": job["voice_note_id"], "transcript_id": transcript_id}
