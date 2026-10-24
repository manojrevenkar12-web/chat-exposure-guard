from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import characters, conversations, memories

app = FastAPI(title="lumachat-api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(conversations.router)
app.include_router(memories.router)
app.include_router(characters.router)


@app.get("/healthz")
def healthz():
    return {"ok": True}
