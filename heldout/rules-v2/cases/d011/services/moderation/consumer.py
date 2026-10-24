import json
import logging

from kafka import KafkaConsumer, KafkaProducer

from .classifier import classify

logging.basicConfig(level=logging.INFO)

BROKERS = [
    "kafka-0.kafka.data.svc.cluster.local:9092",
    "kafka-1.kafka.data.svc.cluster.local:9092",
]


def run() -> None:
    consumer = KafkaConsumer(
        "chat.messages.v1",
        bootstrap_servers=BROKERS,
        group_id="moderation",
        enable_auto_commit=False,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )
    producer = KafkaProducer(
        bootstrap_servers=BROKERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    for record in consumer:
        msg = record.value
        verdict = classify(msg["text"])
        if verdict.flagged:
            logging.getLogger(__name__).warning("moderation flagged message: " + msg["text"])
            producer.send(
                "moderation.flags.v1",
                {"message_id": msg["id"], "labels": verdict.labels},
            )
        consumer.commit()


if __name__ == "__main__":
    run()
