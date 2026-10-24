from fastapi import FastAPI

from app.cors import install_cors
from app.routes import conversations

app = FastAPI()
install_cors(app)
app.include_router(conversations.router)
