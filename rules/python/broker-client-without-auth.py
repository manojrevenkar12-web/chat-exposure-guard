from kafka import KafkaConsumer, KafkaProducer
from confluent_kafka import Consumer

# ruleid: ceg.broker-client-without-auth
consumer = KafkaConsumer("chat-messages", bootstrap_servers="kafka:9092")
# ruleid: ceg.broker-client-without-auth
producer = KafkaProducer(bootstrap_servers=BROKERS, security_protocol="PLAINTEXT")
# ruleid: ceg.broker-client-without-auth
c = Consumer({"bootstrap.servers": "kafka:9092", "group.id": "media", "security.protocol": "PLAINTEXT"})
# ok: ceg.broker-client-without-auth
safe = KafkaConsumer("chat-messages", bootstrap_servers=BROKERS, security_protocol="SASL_SSL", sasl_mechanism="SCRAM-SHA-512")
# ok: ceg.broker-client-without-auth
configured = KafkaProducer(**settings.kafka)
# ok: ceg.broker-client-without-auth
mtls = KafkaProducer(bootstrap_servers=BROKERS, security_protocol="SSL", ssl_certfile="client.pem", ssl_keyfile="client.key")


def caches(os):
    import redis
    # ruleid: ceg.broker-client-without-auth
    a = redis.Redis(host=os.getenv("REDIS_HOST", "redis-master.cache.svc"), port=6379, db=2)
    # ok: ceg.broker-client-without-auth
    b = redis.Redis(host="redis.cache.svc", password=os.environ["REDIS_PASSWORD"], ssl=True)
    # ok: ceg.broker-client-without-auth
    c = redis.Redis(host="localhost")
    # ruleid: ceg.broker-client-without-auth
    d = redis.from_url("redis://cache.internal:6379/0")
    # ok: ceg.broker-client-without-auth
    e = redis.from_url("rediss://:token@cache.internal:6380/0")
    return a, b, c, d, e
