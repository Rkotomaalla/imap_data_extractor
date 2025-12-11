from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def send_notification(notif_data):
    """Methode pour envoyer les notifications Directment"""
    async_to_sync(get_channel_layer().group_send)(
        f"user_{notif_data["assigned_user_id"]}",
        {
                "type": notif_data["type"],                    # success | error | info
                "id": notif_data["notif_id"],
                "title": notif_data["title"],
                "message": notif_data["message"],
                "category": notif_data.get("category", "general"),
                "timestamp": notif_data["timestamp"].isoformat() + "Z",
                "bot_id":notif_data["bot_id_from"]
        }
    )
