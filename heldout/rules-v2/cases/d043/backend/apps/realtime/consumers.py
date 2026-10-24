from urllib.parse import parse_qs

import jwt
from channels.generic.websocket import AsyncJsonWebsocketConsumer


class ChatStreamConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        params = parse_qs(self.scope["query_string"].decode())
        token = params.get("token", [""])[0]
        try:
            payload = jwt.decode(token, verify=False)
        except jwt.DecodeError:
            await self.close(code=4401)
            return
        self.user_id = payload["user_id"]
        self.group = f"user-{self.user_id}"
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if hasattr(self, "group"):
            await self.channel_layer.group_discard(self.group, self.channel_name)

    async def reply_chunk(self, event):
        await self.send_json({"type": "chunk", "data": event["data"]})
