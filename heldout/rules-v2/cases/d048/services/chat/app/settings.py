from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    kafka_bootstrap: str = "kafka-0.kafka.data.svc.cluster.local:9092,kafka-1.kafka.data.svc.cluster.local:9092"
    database_url: str = "postgresql+psycopg://chat@postgres.data.svc.cluster.local/chat"
    chat_model: str = "claude-sonnet-4-5"


settings = Settings()
