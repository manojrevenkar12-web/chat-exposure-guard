from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
# ruleid: ceg.cors-any-origin-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])
# ok: ceg.cors-any-origin-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["https://app.companion.example"], allow_credentials=True)
# ok: ceg.cors-any-origin-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)



def reflect(request, response):
    origin = request.headers.get("origin")
    if origin:
        # ruleid: ceg.cors-any-origin-with-credentials
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"


def allowlisted(request, response, ALLOWED_ORIGINS):
    origin = request.headers.get("origin")
    if origin in ALLOWED_ORIGINS:
        # ok: ceg.cors-any-origin-with-credentials
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
