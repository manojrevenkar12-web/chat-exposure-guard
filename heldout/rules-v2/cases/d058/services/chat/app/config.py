from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    cors_origin_regex: str = r"https?://.*"
    cors_allow_credentials: bool = True
    session_cookie: str = "kc_session"


app_settings = AppSettings()
