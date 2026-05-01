import json
from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import parse_qs


class BaseConsumer(AsyncWebsocketConsumer):
    # Préfixe à surcharger dans chaque consumer enfant
    group_prefix = "user"

    async def connect(self):
        query_string = self.scope.get("query_string", b"").decode()
        query_params = parse_qs(query_string)
        uid_number = query_params.get("user", [None])[0]

        if not uid_number or not uid_number.strip():
            await self.close(code=4001)
            return

        self.user_id = uid_number
        # ✅ Groupe unique par consumer grâce au préfixe
        self.user_group_name = f"{self.group_prefix}_{self.user_id}"

        await self.channel_layer.group_add(self.user_group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({
            "type": "connection_established",
            "message": f"Connexion WebSocket établie pour l'utilisateur {self.user_id}"
        }))

    async def disconnect(self, close_code):
        if hasattr(self, "user_group_name") and self.user_group_name:
            await self.channel_layer.group_discard(self.user_group_name, self.channel_name)

    async def notify(self, event):
        data = event.get("data", {})
        await self.send(text_data=json.dumps(data))


class NotificationConsumer(BaseConsumer):
    # ws/notifications/ → groupe "notif_user_{id}"
    group_prefix = "notif_user"


class ConsoleConsumer(BaseConsumer):
    # ws/consoles/ → groupe "console_user_{id}"
    group_prefix = "console_user"