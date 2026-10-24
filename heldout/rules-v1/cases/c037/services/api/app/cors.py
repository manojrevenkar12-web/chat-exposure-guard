from fastapi import FastAPI, Request
from starlette.responses import Response


def install_cors(app: FastAPI) -> None:
    @app.middleware("http")
    async def cors(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method == "OPTIONS" and origin:
            response = Response(status_code=204)
        else:
            response = await call_next(request)

        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response.headers["Vary"] = "Origin"
        return response
