from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

def send_hello_world_notification():
    """Méthode Python qui envoie un message Hello World"""
    channel_layer = get_channel_layer()
    
    # Envoi du message à tous les clients connectés
    async_to_sync(channel_layer.group_send)(
        'notifications',
        {
            'type': 'send_notification',
            'message': 'Hello World to Drf'
        }
    )