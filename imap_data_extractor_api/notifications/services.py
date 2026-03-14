from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from configurations.services import mongo_service
from datetime import datetime
from imap_data_extractor_api.utils import get_next_sequence_value
from .serializer import MailNotificationSerializer
class Notification:
    def __init__(self, channel_layer=None):
        self.channel_layer = channel_layer or get_channel_layer()
        self.notification_collection = mongo_service.get_collection("notifications")
        self.level_type = {
            0: "WARNING",
            1: "RECEIVED",  
            2: "PENDING",
            3: "RETRY",
            4: "SUCCESS",
            5: "ERROR"
        }

    def save_notification(self, message_data):
        try:
            message_data["notification_id"] = get_next_sequence_value("notifications")
            self.notification_collection.insert_one(message_data)
        except Exception as e:
            print(f"Erreur lors de l'enregistrement de la notification : {e}")
            raise

    def set_message_data(self, user_id, bot_id, message_id, message, type_id):
        level = self.level_type.get(int(type_id), "UNKNOWN")
        scope_id = f"{user_id}_{bot_id}"
        return {
            "scope_id": scope_id,
            "info": level,
            "message": message,
            "notified_at": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "bot_id": bot_id,
            "mail_id": message_id
        }

    def notify_email_process(self, user_id, bot_id, message_id, message, type_id):
        try:
            message_data = self.set_message_data(user_id, bot_id, message_id, message, type_id)
            # async_to_sync(self.channel_layer.group_send)(
            #     f"user_{user_id}_bot_{bot_id}",
            #     {
            #         "type": "notify",
            #         "data": message_data
            #     }
            # )
            if type_id in (3, 4):  # RETRY ou SUCCESS
                self.save_notification(message_data)
        except Exception as e:
            print(f"Erreur lors de l'envoi de la notification : {e}")
            raise


    
    def notify_email_success(self, user_id , bot_ids , message_id , message, type_id):
        try:
            level = self.level_type.get(int(type_id), "UNKNOWN")
            # async_to_sync(self.channel_layer.group_send)(
            #     f"user_{user_id}",
            #     {
            #         "type": "notify",
            #         "data": {
            #             "scope_id": user_id,
            #             "info": level,
            #             "message": message,
            #             "notified_at": datetime.utcnow().isoformat() + "Z",
            #             "user_id": user_id,
            #             "bot_ids": bot_ids,
            #             "mail_id": message_id
            #         }
            #     }
            # )
            if type_id in (3, 4):  # RETRY ou SUCCESS
                self.save_notification({
                        "scope_id": user_id,
                        "info": level,
                        "message": message,
                        "notified_at": datetime.utcnow().isoformat() + "Z",
                        "user_id": user_id,
                        "bot_ids": bot_ids,
                        "mail_id": message_id
                    })
        except Exception as e:
            print(f"Erreur lors de l'envoi de la notification de l email : {e}")
    
    
    
    def notify_user_bots(self, user_id, message_id, message, type_id):
        try:
            bots = mongo_service.get_collection("bots").find({"user_id": user_id})
            for bot in bots:
                self.notify_email_process(user_id, str(bot["_id"]), message_id, message, type_id)
        except Exception as e:
            print(f"Erreur lors de la notification des bots : {e}")
            raise

# Instanciation (à faire une seule fois, par exemple dans un module ou une vue)
notification = Notification()

from channels.exceptions import ChannelFull
from django.db.utils import DatabaseError
from django.utils import timezone
class MailNotification:
    def __init__(self, channel_layer=None):
        self.channel_layer = channel_layer or get_channel_layer()
        self.notification_collection = mongo_service.get_collection("mail_notification")

    
    def save_notification(self, mail_notif_data):
        try:
            

            # Mise à jour ou insertion
            self.notification_collection.insert_one(
                mail_notif_data             
            )

        except Exception as e:
            print(f"Erreur lors de l'enregistrement de la notification : {e}")
            raise
        
    def send_new_mail_notif(self, user_id, bot_id, mail_id, mail_subject, mail_from,from_name,message):
        try:
            if not isinstance(user_id, int) or user_id <= 0:
                raise ValueError("user_id invalide.")            
            notif_data = {
                "user_id": user_id,
                "bot_id": bot_id,
                "mail_id": mail_id,
                "mail_subject" : mail_subject,
                "from" : mail_from,
                "name" : from_name,
                "message": message,
                "is_read": False,
                "created_at": timezone.now().isoformat()
            }

            # Envoi de la notification via WebSocket
            async_to_sync(self.channel_layer.group_send)(
                f"user_{user_id}",
                {
                    "type": "notify",
                    "data": notif_data
                }
            )

            # Sauvegarde ou mise à jour de la notification
            self.save_notification(notif_data)

        except ChannelFull as e:
            print(f"Erreur de canal WebSocket : {e}")
        except DatabaseError as e:
            print(f"Erreur de base de données : {e}")
        except ValueError as e:
            print(f"Erreur de validation : {e}")
        except Exception as e:
            print(f"Erreur inattendue : {e}")  
        
mail_notification  =  MailNotification()


class ConsoleNotification: 
    def send_console_notif(self, user_id ,bot_id,message,type):
        try:
            if not isinstance(bot_id, int):
                raise ValueError("bot_id invalide.")
            notif_data = {
                "type" : type,
                "message": message,
                "user_id" :  user_id,
                "bot_id" : bot_id,
                "notified_at" : {timezone.now().isoformat()}   
            }
            async_to_sync(self.channel_layer.group_send)(
                f"user_{user_id}",
                {
                    "type": "notify",
                    "data": notif_data
                }
            )       
        except ChannelFull as e:
            print(f"Erreur de canal WebSocket : {e}")
        except DatabaseError as e:
            print(f"Erreur de base de données : {e}")
        except ValueError as e:
            print(f"Erreur de validation : {e}")
        except Exception as e:
            print(f"Erreur inattendue : {e}")  
             
             