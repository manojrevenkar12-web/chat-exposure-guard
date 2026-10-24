from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/uploads/{upload_id}")
async def get_upload(request: web.Request) -> web.Response:
    user_id = request["user_id"]  # set by auth_middleware
    upload_id = int(request.match_info["upload_id"])
    pool = request.app["db"]

    row = await pool.fetchrow(
        "SELECT id, owner_id, storage_key, content_type FROM uploads WHERE id = $1",
        upload_id,
    )
    if row is None:
        raise web.HTTPNotFound()

    storage = request.app["storage"]
    body = await storage.read(row["storage_key"])
    request.app["metrics"].incr("uploads.read", tags={"user": str(user_id)})
    return web.Response(body=body, content_type=row["content_type"])


@routes.get("/uploads")
async def list_uploads(request: web.Request) -> web.Response:
    pool = request.app["db"]
    rows = await pool.fetch(
        "SELECT id, content_type, created_at FROM uploads WHERE owner_id = $1 ORDER BY id DESC",
        request["user_id"],
    )
    return web.json_response([{"id": r["id"], "type": r["content_type"]} for r in rows])
