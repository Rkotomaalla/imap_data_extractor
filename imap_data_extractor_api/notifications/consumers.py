import json
from channels.generic.websocket import AsyncWebsocketConsumer
from imap_data_extractor_api.utils import serialize_mongo_doc
from .serializer import NotificationSerializer
from configurations.services import mongo_service
from urllib.parse import parse_qs  # Import correct
class BaseConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        query_string = self.scope.get("query_string", b"").decode()
        query_params = parse_qs(query_string)
        uid_number = query_params.get("user", [None])[0]

        if not uid_number or not uid_number.strip():
            await self.close(code=4001)
            return

        self.user_id = uid_number
        self.user_group_name = f"user_{self.user_id}"

        await self.channel_layer.group_add(self.user_group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({
            "type": "connection_established",
            "message": f"Connexion WebSocket établie pour l'utilisateur {self.user_id}"
        }))

    async def disconnect(self, close_code):
        if hasattr(self, 'user_group_name') and self.user_group_name:
            await self.channel_layer.group_discard(self.user_group_name, self.channel_name)

    async def notify(self, event):
        data = event.get("data", {})
        serialized_data = serialize_mongo_doc(data) if hasattr(data, '_id') else data
        await self.send(text_data=json.dumps(serialized_data))

class NotificationConsumer(BaseConsumer):
    pass

class ConsoleConsumer(BaseConsumer):
    pass