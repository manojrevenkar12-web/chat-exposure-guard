from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://app.kindred.chat",
    "https://beta.kindred.chat",
]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://[a-z0-9-]+\.preview\.kindred\.chat$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
