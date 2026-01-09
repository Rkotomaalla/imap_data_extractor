from celery import shared_task
from  .services  import gmail_service
from configurations.services import mongo_service
from datetime import datetime


@shared_task
def process_gmail_message(user_id, message_id):
    """Récupère le mail Gmail et l’envoie aux bots"""
    gmail_collection=mongo_service.get_collection("gmail_token")
    messages_collection = mongo_service.get_collection("gmail_message")  # nouvelle collection
    """Récupère le mail Gmail et l’envoie aux bots"""
    user_doc = gmail_collection.find_one({"user_id": user_id})
    if not user_doc:
        return

    # Récupérer le service Gmail avec gestion du refresh token
    service = gmail_service.get_gmail_service(user_id)
    messages = service.users().messages().list(userId="me", maxResults=10).execute()
    print(f"\n========================================================\n{messages.get("messages", [])}")

    # Récupérer le mail complet
    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full"
    ).execute()
    
    payload = message['payload']
    
    # Extraire les infos importantes
    headers = {h['name']: h['value'] for h in message.get('payload', {}).get('headers', [])}
    attachments = gmail_service.extract_attachments(service,user_id,message_id,payload)
    has_attachment = len(attachments) > 0
    mail_data = {
        "user_id": user_id,
        "gmail_message_id": message.get("id"),
        "thread_id": message.get("threadId"),
        "from": headers.get("From"),
        "to": headers.get("To"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
        "snippet": message.get("snippet"),
        "label_ids": message.get("labelIds", []),
        "received_at": datetime.utcnow(),
        "has_attachment" : has_attachment
    }

    # Stocker dans MongoDB
    messages_collection.update_one(
        {"gmail_message_id": message.get("id")},
        {"$set": mail_data},
        upsert=True
    )
        