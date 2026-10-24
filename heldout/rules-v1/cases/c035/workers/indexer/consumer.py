import json
import logging
import os

from kafka import KafkaConsumer

log = logging.getLogger("indexer")


def build_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        "chat.message-created",
        bootstrap_servers=os.environ["KAFKA_BOOTSTRAP"].split(","),
        group_id="search-indexer",
        security_protocol="SASL_SSL",
        sasl_mechanism="SCRAM-SHA-512",
        sasl_plain_username=os.environ["KAFKA_USERNAME"],
        sasl_plain_password=os.environ["KAFKA_PASSWORD"],
        ssl_cafile="/etc/kafka/ca.crt",
        enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )


def run(index) -> None:
    consumer = build_consumer()
    for record in consumer:
        event = record.value
        index.upsert_message(event["message_id"])
        consumer.commit()
        log.debug("indexed message_id=%s offset=%d", event["message_id"], record.offset)
