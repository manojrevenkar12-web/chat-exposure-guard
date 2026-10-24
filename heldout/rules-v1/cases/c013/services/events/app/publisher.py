import json
import os
from datetime import datetime, timezone

from kafka import KafkaProducer

BOOTSTRAP = os.environ.get(
    "KAFKA_BOOTSTRAP",
    "kafka-0.kafka.data.svc.cluster.local:9092,kafka-1.kafka.data.svc.cluster.local:9092",
)

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP.split(","),
    acks="all",
    linger_ms=20,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    key_serializer=lambda k: k.encode("utf-8"),
)


def message_created(conversation_id: str, message_id: str, user_id: str) -> None:
    producer.send(
        "chat.message-created",
        key=conversation_id,
        value={
            "conversation_id": conversation_id,
            "message_id": message_id,
            "user_id": user_id,
            "at": datetime.now(timezone.utc).isoformat(),
        },
    )
