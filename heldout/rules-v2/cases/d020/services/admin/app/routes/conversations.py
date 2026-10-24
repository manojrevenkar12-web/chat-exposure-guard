from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..auth import require_staff
from ..db import get_engine

router = APIRouter(prefix="/admin", dependencies=[Depends(require_staff)])


@router.get("/conversations")
async def list_conversations(
    sort: str = Query("created_at"),
    direction: str = Query("desc"),
    engine: AsyncEngine = Depends(get_engine),
):
    stmt = text(
        "SELECT id, user_id, character_id, title, created_at "
        "FROM conversations ORDER BY " + sort + " " + direction + " LIMIT 100"
    )
    async with engine.connect() as conn:
        rows = (await conn.execute(stmt)).mappings().all()
    return [dict(r) for r in rows]
