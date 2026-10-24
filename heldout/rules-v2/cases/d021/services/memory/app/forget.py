import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .auth import current_user_id
from .db import get_pool

router = APIRouter()


class ForgetRequest(BaseModel):
    topic: str


async def forget_topic(pool: asyncpg.Pool, user_id: int, topic: str) -> int:
    sql = "DELETE FROM memories WHERE user_id = {} AND topic = '{}'".format(user_id, topic)
    async with pool.acquire() as conn:
        status = await conn.execute(sql)
    return int(status.split()[-1])


@router.post("/memories/forget")
async def forget(
    body: ForgetRequest,
    user_id: int = Depends(current_user_id),
    pool: asyncpg.Pool = Depends(get_pool),
):
    removed = await forget_topic(pool, user_id, body.topic)
    return {"removed": removed}
