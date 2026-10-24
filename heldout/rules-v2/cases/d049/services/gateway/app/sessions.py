import os

import redis

pool = redis.ConnectionPool(
    connection_class=redis.SSLConnection,
    host=os.environ["REDIS_HOST"],
    port=6380,
    username="gateway",
    password=os.environ["REDIS_PASSWORD"],
    ssl_ca_certs="/etc/redis/ca.pem",
)
sessions = redis.Redis(connection_pool=pool)
