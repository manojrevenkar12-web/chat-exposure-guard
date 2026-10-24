import os
import time

import redis
from fastapi import HTTPException

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis-master.cache.svc.cluster.local"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=2,
    decode_responses=True,
)


def limit_messages(user_id: str, per_minute: int = 20) -> None:
    window = int(time.time() // 60)
    key = f"rl:msg:{user_id}:{window}"
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, 120)
    count, _ = pipe.execute()
    if count > per_minute:
        raise HTTPException(status_code=429, detail="slow down")
