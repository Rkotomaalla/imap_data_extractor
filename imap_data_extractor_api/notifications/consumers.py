import json
from channels.generic.websocket import AsyncWebsocketConsumer
import json
from django.conf import settings
from imap_data_extractor_api.utils import serialize_mongo_doc
from .serializer import NotificationSerializer
from configurations.services import mongo_service

notif_collection = mongo_service.get_collection('notifications')
class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope["user"].is_anonymous:
            await self.close()
            return
        
        self.user_id = str(self.scope["user"].id)
        self.group_name = f"user_{self.user_id}"
        
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        
        # Envoie toutes les notifications non lues à la connexion
        cursor = notif_collection.find(
            {"assigned_user_id": self.user_id, "read": False}
        ).sort("timestamp", -1)

        for notif in cursor:
            notif_data=serialize_mongo_doc(notif)
            await self.send(text_data=json.dumps({
                "type": notif_data["type"],                    # success | error | info
                "id": notif_data["notif_id"],
                "title": notif_data["title"],
                "message": notif_data["message"],
                "category": notif_data.get("category", "general"),
                "timestamp": notif_data["timestamp"].isoformat() + "Z",
                "bot_id":notif_data["bot_id_from"]
            }))
            