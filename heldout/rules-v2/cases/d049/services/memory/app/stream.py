import os
import ssl

from aiokafka import AIOKafkaConsumer


def build_consumer() -> AIOKafkaConsumer:
    ctx = ssl.create_default_context(cafile="/etc/kafka/ca.pem")
    return AIOKafkaConsumer(
        "memory.extracted.v1",
        bootstrap_servers=os.environ["KAFKA_BOOTSTRAP"],
        group_id="memory-writer",
        security_protocol="SASL_SSL",
        sasl_mechanism="SCRAM-SHA-512",
        sasl_plain_username=os.environ["KAFKA_USERNAME"],
        sasl_plain_password=os.environ["KAFKA_PASSWORD"],
        ssl_context=ctx,
        enable_auto_commit=False,
    )
