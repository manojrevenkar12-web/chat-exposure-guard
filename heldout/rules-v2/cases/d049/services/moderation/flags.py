import os

from confluent_kafka import Producer

producer = Producer(
    {
        "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP"],
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": "SCRAM-SHA-512",
        "sasl.username": os.environ["KAFKA_USERNAME"],
        "sasl.password": os.environ["KAFKA_PASSWORD"],
        "ssl.ca.location": "/etc/kafka/ca.pem",
        "acks": "all",
    }
)
