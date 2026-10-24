from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import conversations

ALLOWED_ORIGINS = [
    "https://app.lumachat.example.com",
    "https://www.lumachat.example.com",
]

app = FastAPI(title="lumachat-api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(conversations.router)
