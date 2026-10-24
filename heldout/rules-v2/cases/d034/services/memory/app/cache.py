import os
import pickle

import redis.asyncio as aioredis

cache = aioredis.Redis(
    host=os.getenv("CACHE_HOST", "redis-cache.chat.svc.cluster.local"),
    port=6379,
    db=2,
)

TTL_SECONDS = 3600


async def get_embeddings(user_id: int):
    raw = await cache.get(f"emb:{user_id}")
    if raw is None:
        return None
    return pickle.loads(raw)


async def put_embeddings(user_id: int, vectors) -> None:
    await cache.set(f"emb:{user_id}", pickle.dumps(vectors), ex=TTL_SECONDS)
