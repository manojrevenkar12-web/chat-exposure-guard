from datetime import timedelta

from google.cloud import storage

_client = storage.Client()
VOICE_BUCKET = "lumachat-voice-notes-eu"


def voice_note_link(object_name: str) -> str:
    blob = _client.bucket(VOICE_BUCKET).blob(object_name)
    return blob.generate_signed_url(
        version="v4",
        expiration=timedelta(days=30),
        method="GET",
        response_type="audio/ogg",
    )
