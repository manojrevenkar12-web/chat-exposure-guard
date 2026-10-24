import logging

from fastapi import HTTPException

log = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, redis, limit_per_minute: int) -> None:
        self.redis = redis
        self.limit = limit_per_minute

    async def check(self, user_id: int, chat_message) -> None:
        key = f"rl:{user_id}"
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, 60)
        if count > self.limit:
            message = f"rate limit hit for user {user_id} ({count}/{self.limit} per minute)"
            log.warning(message)
            raise HTTPException(status_code=429, detail="slow down")
        log.debug("accepted message id=%s len=%d", chat_message.id, len(chat_message.text))
