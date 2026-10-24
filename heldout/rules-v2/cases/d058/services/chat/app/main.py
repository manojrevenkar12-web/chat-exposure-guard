from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import app_settings
from .routes import conversations, messages

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=app_settings.cors_origin_regex,
    allow_credentials=app_settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(conversations.router)
app.include_router(messages.router)
