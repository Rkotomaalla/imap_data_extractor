# gmail_services.py
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request    
import base64
import os
from django.conf import settings
from datetime import datetime

from configurations.services import mongo_service

class GmailServices:
    def __init__(self):
        self.gmail_collection = mongo_service.get_collection('gmail_token')
        self.attachment_collection = mongo_service.get_collection('attachment_email')
    def  extract_attachments(self,service, user_id, message_id ,payload):
        attachments =  []
        def walk_parts(parts):
            for part in parts:
                filename = part.get("filename")
                body = part.get("body",{})
                attachment_id = body.get("attachmentId")
                
                #Detection piece jointe
                if filename and attachment_id:
                    att = service.users().messages().attachments().get(
                        userId = "me",
                        messageId = message_id,
                        id = attachment_id                        
                    ).execute()
                    
                    data = att.get("data")
                    file_data = base64.urlsafe_b64decode(data.encode("UTF-8"))
                    attachments.append({
                        "filename": filename,
                        "mime_type": part.get("mimeType"),
                        "size": body.get("size"),
                        "data": file_data
                    })            
                # Parcours récursif si sous-parts
                if part.get("parts"):
                    walk_parts(part["parts"])
                    
        def save_attachments():
            user_folder = f"user_{user_id}"
            mail_folder = f"mail_{message_id}"
            save_dir = os.path.join(settings.BASE_MEDIA_PATH, user_folder, mail_folder)
            os.makedirs(save_dir, exist_ok=True)
            
            for att in attachments:
                file_path = os.path.join(save_dir, att["filename"])
                with open(file_path, "wb") as f:
                        f.write(att["data"])
                # Stocker le chemin dans MongoDB
                attachment_doc = {
                    "user_id": user_id,
                    "mail_id": message_id,
                    "filename": att["filename"],
                    "mime_type": att["mime_type"],
                    "size": att["size"],
                    "storage_type": "local",
                    "storage_path": file_path,
                    "created_at": datetime.utcnow()
                }
                self.attachment_collection.insert_one(attachment_doc)        
                
                   
        if payload.get("parts"):
            walk_parts(payload.get("parts"))
        if len(attachments) > 0:
            save_attachments()
        return attachments
    
    
    
    def get_gmail_auth_url(self,user_id):
        """
            Génère l'URL d'autorisation OAuth Gmail pour un utilisateur.
            user_id : identifiant interne de ton utilisateur dans MongoDB/Django
        """
        flow = Flow.from_client_config(
            {
                "web"  : {
                    "client_id": settings.GMAIL_CLIENT_ID,
                    "client_secret": settings.GMAIL_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    
                }
            },
            scopes=[
                "https://www.googleapis.com/auth/gmail.readonly"
            ],
            redirect_uri=settings.GMAIL_REDIRECT_URI
        )
        # Optionnel : tu peux passer un state pour sécuriser l'utilisateur
        auth_url, state = flow.authorization_url(
            access_type="offline",   # permet d'obtenir un refresh_token
            include_granted_scopes="true",
            state=f"user_{user_id}",
            prompt="select_account consent"
        )
        return auth_url, state
    
    def exchange_code_for_token(self,code, state = None):
        """
            Échange le code OAuth Gmail contre access_token et refresh_token
        """
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GMAIL_CLIENT_ID,
                    "client_secret": settings.GMAIL_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=settings.GMAIL_SCOPES,
            redirect_uri=settings.GMAIL_REDIRECT_URI
        )
        flow.fetch_token(code=code)
        credentials = flow.credentials
        return {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "expires_at": credentials.expiry  # datetime object
        }
        
    def get_gmail_service(self,user_id):
            """
                Récupère le service Gmail pour un utilisateur en utilisant MongoDB
                et gère automatiquement le refresh si nécessaire
            """
            user_doc = self.gmail_collection.find_one({"user_id": user_id})
            if not user_doc:
                    raise Exception("Utilisateur non connecté à Gmail")
            access_token = user_doc.get("access_token")
            refresh_token = user_doc.get("refresh_token")
            expires_at = user_doc.get("expires_at")      
            
            if expires_at is None or datetime.utcnow() >= expires_at:         
                    if not refresh_token:
                        raise Exception("Refresh token manquant, l'utilisateur doit réautoriser l'app")
                    # Renouveler le token
                    creds = Credentials(
                        token=access_token,
                        refresh_token=refresh_token,
                        client_id=settings.GMAIL_CLIENT_ID,
                        client_secret=settings.GMAIL_CLIENT_SECRET,
                        token_uri="https://oauth2.googleapis.com/token"
                    )        
                    creds.refresh(Request())
                    # Mettre à jour MongoDB
                    self.gmail_collection.update_one(
                        {"user_id": user_id},
                        {"$set": {
                            "access_token": creds.token,
                            "expires_at": creds.expiry,
                            "updated_at": datetime.utcnow()
                        }}
                    )
                    access_token = creds.token
                    expires_at = creds.expiry
                # Créer le service Gmail
            creds = Credentials(
                    token=access_token,
                    refresh_token=refresh_token,
                    client_id=settings.GMAIL_CLIENT_ID,
                    client_secret=settings.GMAIL_CLIENT_SECRET,
                    token_uri="https://oauth2.googleapis.com/token"
                )
            service = build('gmail', 'v1', credentials=creds)
            return service
            
gmail_service = GmailServices()