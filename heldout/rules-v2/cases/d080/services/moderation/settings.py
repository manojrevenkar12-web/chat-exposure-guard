import os

MODERATION_API_TOKEN = os.environ["MODERATION_API_TOKEN"]
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client_secret = os.environ.get("OAUTH_CLIENT_SECRET", "change-me")
