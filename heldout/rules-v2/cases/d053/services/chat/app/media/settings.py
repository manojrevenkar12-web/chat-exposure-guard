from pydantic_settings import BaseSettings, SettingsConfigDict


class MediaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MEDIA_")

    bucket: str = "kindred-private-media"
    region: str = "eu-west-1"
    media_url_ttl_seconds: int = 60 * 60 * 48
    max_upload_mb: int = 20


media_settings = MediaSettings()
