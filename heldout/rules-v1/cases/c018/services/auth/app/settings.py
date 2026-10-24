from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env")

    google_client_id: str = "lumachat-web.apps.googleusercontent.com"
    google_client_secret: str = "Vf3qT9zLm2Rk8sWb1nYc6uHd"
    oauth_redirect_url: str = "https://app.lumachat.example.com/auth/callback"

    session_cookie_name: str = "luma_session"
    jwt_issuer: str = "https://auth.lumachat.example.com"
    jwt_audience: str = "lumachat-api"
    access_token_ttl_seconds: int = 900


settings = Settings()
