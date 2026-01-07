import msal
import requests
from django.conf import settings
from datetime import datetime, timedelta
from configurations.services import mongo_service
from django.conf import settings
class OutlookIntegrationUtils:
    def __init__(self):
       self.collection =  mongo_service.get_collection('outlook_token') 
    def get_valid_access_token(self,user_id):
        """
        Docstring for get_valid_access_token
        
        :param user_id: Description
        """
        
        token_doc  =  self.collection.find_one({"user_id" : user_id})
        
        if not token_doc or not token_doc.get("refresh_token"):
            raise Exception("Aucun token Outlook pour cette utilsateur")
        
        # si le token est encore valide
        if token_doc["expires_at"] > datetime.utcnow()+timedelta(minutes=5):
            return token_doc["access_token"]
        
        # sinon on rafraichi
        app = msal.ConfidentialClientApplication(
            client_id=settings.AZURE_CLIENT_ID,
            client_credential=settings.AZURE_CLIENT_SECRET,
            authority=settings.AZURE_AUTHORITY,
        )
        result = app.acquire_token_by_refresh_token(
            refresh_token=token_doc["refresh_token"],
            scopes=["https://graph.microsoft.com/Mail.Read"]
        )
        if "error" in result:
            raise Exception(f"Échec rafraîchissement token: {result.get('error_description')}")

        new_access_token = result["access_token"]
        new_refresh_token = result.get("refresh_token", token_doc["refresh_token"])
        new_expires_at = datetime.utcnow() + timedelta(seconds=result.get("expires_in", 3599))
        
            # Mise à jour en base
        self.collection.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "expires_at": new_expires_at,
                    "updated_at": datetime.utcnow(),
                }
            }
        )

        return new_access_token
    
    def create_graph_subscription(self,user_id):
        """Crée une webhook subscription pour /me/messages (nouveaux mails)"""
        access_token = self.get_valid_access_token(user_id)
        url = settings.SUBSCRIPTION_URL
        webhook_url = settings.WEBHOOK_URL
        
        payload = {
            "changeType": "created",
            "notificationUrl": webhook_url,
            "resource": "me/messages",
            "expirationDateTime": (datetime.utcnow() + timedelta(days=2, hours=23)).isoformat() + "Z",
            "clientState": "secret-client-state-123"  # Secret connu seulement de toi pour vérifier les notifs
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 201:
            return response.json().get("id")
        else:
            print("Erreur lors de la création de subscription", response.text)
            return None
        
    def delete_graph_subscription(self,subscription_id,user_id):
        access_token  = self.get_valid_access_token(user_id)
        url = f"https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}"
        headers = {"Authorization": f"Bearer {access_token}"}
        requests.delete(url, headers=headers)
        
outlook_utils =  OutlookIntegrationUtils()