import aiohttp_cors
from aiohttp import web

from .handlers import routes
from .middleware import auth_middleware


def build_app() -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app.add_routes(routes)

    cors = aiohttp_cors.setup(
        app,
        defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods=["GET", "POST", "DELETE"],
            )
        },
    )
    for route in list(app.router.routes()):
        cors.add(route)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), port=8080)
