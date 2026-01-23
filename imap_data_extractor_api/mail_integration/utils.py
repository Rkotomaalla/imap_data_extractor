import os
from django.conf import settings
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


def notify_user(user_id, message_data: dict):
    """
    envoi de notification en temps reel aux utilisateur
    
    :param user_id: Description
    :param message_data: Description
    :type message_data: dict
    """
    channel_layer   = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{user_id}",
        {
            "type" : "notify",
            "data" : message_data
        }
    ) 
    