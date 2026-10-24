from aiohttp import web

from .sessions import resolve_session


@web.middleware
async def auth_middleware(request: web.Request, handler):
    token = request.cookies.get("kc_session")
    session = await resolve_session(request.app["redis"], token) if token else None
    if session is None:
        raise web.HTTPUnauthorized()
    request["user_id"] = session.user_id
    return await handler(request)
