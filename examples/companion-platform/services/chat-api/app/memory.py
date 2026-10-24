from .db import Memory, async_session


async def memories_for(user_id):
    async with async_session() as db:
        rows = await db.execute(Memory.select().where(Memory.user_id == user_id))
        return [r.text for r in rows]
