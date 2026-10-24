import json

import torch
from kafka import KafkaConsumer

consumer = KafkaConsumer("chat-messages", bootstrap_servers="kafka.internal:9092", group_id="memory")
summariser = torch.load("/models/summariser.pt")


def run(store):
    for record in consumer:
        msg = json.loads(record.value)
        facts = summariser(msg["content"])
        store.save(msg["user_id"], facts)
