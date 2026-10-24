from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import public_characters

app = FastAPI(title="character-catalog")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "Content-Type"],
)

app.include_router(public_characters.router)
