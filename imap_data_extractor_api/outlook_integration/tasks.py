from celery import shared_task
import requests
from django.conf import settings
from datetime import datetime, timedelta
from .utils import outlook_utils  # ta fonction existante
from configurations.services import mongo_service

class OutlookTasks:
    def __init__(self):
        self.extracted_mail_collection = mongo_service.get_collection("extract_mail")
    @shared_task
    def  process_new_outlook_email(self,user_id, message_id):
        """
            tache asynchrone : recupere et traite un nouveau mail
        """
        try:
            access_token = outlook_utils.get_valid_access_token(user_id)
            url =  f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Prefer": "outlook.body-content-type=\"text\""
            }
            params = {
                "$select": "subject,from,bodyPreview,body,receivedDateTime,hasAttachments,attachments"
            }
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != 200:
                print(f"Erreur Graph API pour user {user_id}: {response.text}")
                return

            email_data = response.json()

            self.extracted_mail_collection.insert_one({
                "user_id": user_id,
                "message_id": message_id,
                "subject": email_data.get("subject"),
                "from": email_data.get("from"),
                "received_date": email_data.get("receivedDateTime"),
                "body_preview": email_data.get("bodyPreview"),
                "body": email_data.get("body", {}).get("content"),
                "has_attachments": email_data.get("hasAttachments"),
                "processed_at": datetime.utcnow(),
                "raw_data": email_data  # optionnel
            })
            print(f"Email traité avec succès pour user {user_id}: {email_data.get('subject')}")
        except Exception as e:
            print(f"Erreur traitement email {message_id} pour user {user_id}: {str(e)}")
outlook_task = OutlookTasks()