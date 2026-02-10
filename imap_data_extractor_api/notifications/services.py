from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from configurations.services import mongo_service
from  datetime import datetime
from imap_data_extractor_api.utils import get_next_sequence_value
class Notification:
    def __init__(self):
        self.channel_layer = get_channel_layer()
        self.notification_collection = mongo_service.get_collection("notifications")
        self.level_type = {
            0 : "WARNING",
            1 : "RECEIVED",
            2 : "PENDING",
            3 : "RETRY",
            4 :"SUCCESS",
            5 : "ERROR"
        }
        
    def save_notification(self, message_data):
        try:
            # Ajouter un ID unique
            message_data["notification_id"] = get_next_sequence_value("notifications")

            # Enregistrer dans la collection MongoDB
            self.notification_collection.insert_one(message_data)

        except Exception as e:
            # Tu peux loguer ici si tu veux
            print(f"Erreur lors de l'enregistrement de la notification : {e}")
            # Remonter l'exception si nécessaire
            raise
    
    def set_message_data(self, user_id, bot_id , message_id, message,type_id):
        level =self.level_type.get(int(type_id))
        scope_id = f"{user_id}_{bot_id}"
        message_data = {
            "scope_id" : scope_id,
            "info":level,
            "message":  message,
            "notified_at" : datetime.utcnow().isoformat(),
            "user_id": user_id,
            "bot_id": bot_id,
            "mail_id": message_id
        }
        return message_data
        
        
    def notify_email_process(self, user_id,bot_id,message_id,message,type_id):
        message_data= self.set_message_data(user_id,bot_id,message_id,message,type_id)
        async_to_sync(self.channel_layer.group_send)(
            f"user_{user_id}",
            {
                "type": "notify",  # correspond à async def notify(self, event)
                "data": message_data
            }
        )
        # sauvegarder uniquement SUCCESS (4) ou RETRY (3)
        if type_id in (4, 5):
            self.save_notification(message_data)
        
        
            
notification = Notification()
    