import json
from channels.generic.websocket import AsyncWebsocketConsumer
import json
from django.conf import settings
from imap_data_extractor_api.utils import serialize_mongo_doc
from .serializer import NotificationSerializer
from configurations.services import mongo_service

notif_collection = mongo_service.get_collection('notification')

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]
        
        if user.is_anonymous:
            await self.close(code=4001)  # Code personnalisé pour "non authentifié"
            return
        
        self.user_id = str(user.id)
        self.group_name = f"user_{self.user_id}"
        
        # Ajouter au groupe
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        
        # Accepter la connexion
        await self.accept()
        
        # Envoyer un message de connexion réussie (optionnel)
        await self.send(text_data=json.dumps({
            "type": "connection_established",
            "message": "Connexion WebSocket établie"
        }))
    
    async def disconnect(self, close_code):
        # Vérifier si group_name existe avant de l'utiliser
        if hasattr(self, 'group_name') and self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
    
    async def notify(self, event):
        """
        Méthode appelée par `notify_user`.
        Envoie les données de notification au WebSocket.
        """
        await self.send(text_data=json.dumps(event["data"]))
            