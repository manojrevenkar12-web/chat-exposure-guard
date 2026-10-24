import json

from confluent_kafka import Producer

from ..settings import settings


def _producer_config() -> dict:
    return {
        "bootstrap.servers": settings.kafka_bootstrap,
        "client.id": "chat-api",
        "acks": "all",
        "enable.idempotence": True,
        "compression.type": "zstd",
        "linger.ms": 20,
    }


class EventPublisher:
    def __init__(self) -> None:
        self._producer = Producer(_producer_config())

    def message_created(self, conversation_id: str, message_id: str, user_id: int) -> None:
        payload = {"conversation_id": conversation_id, "message_id": message_id, "user_id": user_id}
        self._producer.produce(
            "chat.messages.created.v1",
            key=conversation_id.encode(),
            value=json.dumps(payload).encode(),
        )
        self._producer.poll(0)

    def close(self) -> None:
        self._producer.flush(10)
