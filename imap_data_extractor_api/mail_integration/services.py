# gmail_services.py
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request    
import base64
import os
from django.conf import settings
from datetime import datetime, timezone
import logging
from configurations.services import mongo_service
from pymongo.errors import DuplicateKeyError
from notifications.services import notification,mail_notification,console_notification
from imap_data_extractor_api.utils import get_next_sequence_value
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

from email.utils import parseaddr   
class GmailServices:
    def __init__(self):
        self.gmail_collection = mongo_service.get_collection('gmail_token')
        self.attachment_collection = mongo_service.get_collection('attachment_email')
        self.filtered_emails_collection =  mongo_service.get_collection("filtered_emails")
    
    
    def sort_rules_by_indexed_priority(self,rules,indexed_map):
        def get_priority(rule):
            is_indexed = indexed_map.get(f"{rule["field_id"]}", False)
            logger.info(f"regles  = {rule}")
            return 0 if is_indexed else 1          # 0 = prioritaire, 1 = après
        priorities = [get_priority(r) for r in rules]
        return {
            "result" : sorted(rules, key=get_priority),
            "true" : priorities.count(0),
            "false" : priorities.count(1)
        }
        


    def decode_body(self,data):
        if not data:
            return None
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")



    def extract_mail_data(self,user_id: int | None = None,message: dict | None = None, bot_id: int | None = None, has_attachment: bool | None = None):
        if not message:
            return None
        
        payload =message.get("payload" , {})
        headers =  payload.get("headers" , [])
        
        header_map = {h["name"].lower() : h["value"] for h in headers}  
        
        email_data =  {
            "bot_id" : bot_id,
            "user_id"  : user_id,
            "gmail_message_id": message.get("id"),
            "thread_id": message.get("threadId"),
            "from": header_map.get("from"),
            "to": header_map.get("to"),
            "cc": header_map.get("cc"),
            "subject": header_map.get("subject"),
            "date": header_map.get("date"),
            "snippet": message.get("snippet"),
            "labels": message.get("labelIds"),
            "internal_date": datetime.fromtimestamp(
                int(message.get("internalDate")) / 1000
            ),
            "received_at": datetime.utcnow(),
            "has_attachment": has_attachment,
            "body_text": None,
            "body_html": None
        }
        
        def walk_parts(parts):
            for part in parts:
                if part.get("filename"):
                    continue

                mime = part.get("mimeType")
                body = part.get("body", {}).get("data")

                if mime == "text/plain" and not email_data["body_text"]:
                    email_data["body_text"] = self.decode_body(body)
                elif mime == "text/html" and not email_data["body_html"]:
                    email_data["body_html"] = self.decode_body(body)

                # récursif (multipart)
                if part.get("parts"):
                    walk_parts(part["parts"])

        # Cas simple (email sans multipart)
        if payload.get("body", {}).get("data"):
            email_data["body_text"] = self.decode_body(payload["body"]["data"])

        # Cas multipart
        if payload.get("parts"):
            walk_parts(payload["parts"])

        return email_data        
            
            
            
    def extract_attachments(self, payload):
        if not payload:
            return []
        attachments = []
        def walk_parts(parts):
            for part in parts:
                filename = part.get("filename")
                body = part.get("body", {})

                # pièce jointe réelle (non inline)
                if (
                    filename
                    and body.get("attachmentId")
                    and body.get("size", 0) > 0
                ):
                    attachments.append({
                        "filename": filename,
                        "mime_type": part.get("mimeType"),
                        "size": body.get("size", 0),
                        "attachment_id": body.get("attachmentId")
                    })

                if part.get("parts"):
                    walk_parts(part["parts"])

        walk_parts(payload.get("parts", []))
        return attachments
      
            
    def fetch_gmail_attachment(self, service, message_id: str, attachment_id: str) -> bytes | None:
        try:
            response = service.users().messages().attachments().get(
                userId="me",
                messageId=message_id,
                id=attachment_id
            ).execute()

            data = response.get("data")
            if not data:
                logger.warning(
                    f"Aucune donnée pour attachment_id={attachment_id}, message_id={message_id}"
                )
                return None

            return base64.urlsafe_b64decode(data.encode("utf-8"))

        except Exception as e:
            logger.error(
                f"Erreur fetch_gmail_attachment "
                f"(message_id={message_id}, attachment_id={attachment_id}) : {e}"
            )
            return None
        
        
    def save_attachments(self,service,user_id : int | None = None,message_id : int | None = None,attachments : list | None = None ):
        user_folder = f"user_{user_id}"
        mail_folder = f"mail_{message_id}"
        save_dir = os.path.join(settings.BASE_MEDIA_PATH, user_folder, mail_folder)
        os.makedirs(save_dir, exist_ok=True)
        for att in attachments:
            try:
                attachment_email_id=get_next_sequence_value("attachment_email_id")
                file_path = os.path.join(save_dir, att["filename"])
                attachment_id = att.get("attachment_id",None)
                file_data = self.fetch_gmail_attachment(service, message_id,attachment_id)
                
                if not file_data:
                    return False
                
                with open(file_path, "wb") as f:
                        f.write(file_data)
                # Stocker le chemin dans MongoDB
                attachment_doc = {
                    # "attachment_email_id" : attachment_email_id,
                    "user_id": user_id,
                    "gmail_message_id": message_id,
                    "filename": att["filename"],
                    "mime_type": att["mime_type"],
                    "size": att["size"],
                    "storage_type": "local",
                    "storage_path": file_path,
                    "created_at": datetime.utcnow(),
                    "attachment_id": attachment_id
                }
                self.attachment_collection.update_one(
                    {"attachment_email_id":attachment_email_id },
                    {"$setOnInsert": attachment_doc},
                    upsert=True
                )
            except Exception as e:
                # Nisy Erreur
                logger.error(f"Erreur save_attachments  pour {message_id}: {e}")
                return False
        logger.info(f"Piece Jointes  enregistrées")
        return True
    
    
    def save_email(self, mail_data):
        try:
            filtered_emails_id = get_next_sequence_value("filtered_emails_id")
            # mail_data["filtered_emails_id"] = filtered_emails_id
            self.filtered_emails_collection.update_one(
                {"filtered_emails_id":filtered_emails_id},
                {"$setOnInsert": mail_data},
                upsert=True
            )
            logger.info(f"Email enregistré : {mail_data['gmail_message_id']}")
            
            mail_subject = mail_data["subject"]
            mail_id = mail_data["gmail_message_id"]  # Assurez-vous que message_id est défini
            user_id = mail_data["user_id"]  # Assurez-vous que user_id est défini
            
            email_string = mail_data["from"]
            from_email = email_string.strip('<>').split()[-1]

            from_name, from_email = parseaddr(email_string)
            
            # Préparation des données pour la notification
            bot_id = mail_data.get("bot_id")
            
            message = f"Mail enregistré avec succès: id_mail : {mail_id}"

            # Envoi de la notification
            mail_notification.send_new_mail_notif(user_id, bot_id, mail_id , mail_subject,from_email,from_name, message)

            logger.info(f"\nUn mail a été enregistré, id mail {mail_id} par l'utilisateur {user_id}\n")      
            
            return True
        except DuplicateKeyError:
            # Efa misy ilay Email
            logger.warning(f"Email déjà existant : {mail_data['gmail_message_id']}")
            return True
        except Exception as e:
             # Nisy Erreur
            logger.error(f"Erreur save_email pour {mail_data.get('gmail_message_id')}: {e}")
            return False
               
        
    def delete_email_rollback(self,message_id):
        {
            self.filtered_emails_collection.delete_one(
                {"gmail_message_id": message_id}
            )
        }
    
    def save_email_and_attachments(self, service, user_id, message_id, mail_extracted_data, attachment_extracted_data) -> bool:
        try:
            # Sauvegarde Email
            try:
                date = mail_extracted_data['date']
                date_obj = parsedate_to_datetime(date).astimezone(timezone.utc)
                mail_extracted_data['date'] = date_obj  
                saving_mail_result = self.save_email(mail_extracted_data)
                if not saving_mail_result:
                    message =  f"Echec sauvegarde email : {message_id}"
                    logger.error(f"Echec sauvegarde email : {message_id}")
                    console_notification.send_console_notif(user_id,mail_extracted_data.get("bot_id"),message,2)        
                    
                    return False
                message =  f"Nouveau mail enregistré : {message_id}"
                console_notification.send_console_notif(user_id,mail_extracted_data.get("bot_id"),message,1)        
                
            except Exception as e:
                logger.error(f"Exception save_email : {e}")
                return False

            # Sauvegarde Attachments
            if attachment_extracted_data:
                try:
                    saving_att_result = self.save_attachments(
                        service, user_id, message_id, attachment_extracted_data
                    )
                    if not saving_att_result:
                        self.delete_email_rollback(message_id)
                        logger.error(f"Rollback : échec insertion attachments pour email {message_id}")
                        return False  # ✅ Seulement si échec
                except Exception as e:
                    self.delete_email_rollback(message_id)
                    logger.error(f"Rollback exception attachments email {message_id} : {e}")
                    return False

            return True  # ✅ Ce return manquait complètement

        except Exception as e:
            logger.error(f"Erreur inattendue save_email_and_attachments {message_id}: {e}")
            return False
        
        
    # def delete_email_rollback(self): 
    
    
    
    def  extract_and_save_attachments(self,service, user_id, message_id ,payload):
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
                        "data": file_data,
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
        user_doc = self.gmail_collection.find_one({"user_id": user_id})
        already_connected = user_doc and user_doc.get("refresh_token")
        
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
            prompt="select_account" if already_connected else "select_account consent"
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
            "refresh_token": credentials.refresh_token or None,
            "expires_at": credentials.expiry  # datetime object
        }
        
        
        

    def get_gmail_service(self, user_id):
        user_doc = self.gmail_collection.find_one({"user_id": user_id})
        already_connected = user_doc and user_doc.get("refresh_token")
        if not user_doc:
            raise GmailNotConnectedException()

        access_token = user_doc.get("access_token")
        refresh_token = user_doc.get("refresh_token")
        expires_at = user_doc.get("expires_at")

        if not refresh_token:
            raise Exception("Refresh token manquant, l'utilisateur doit réautoriser l'app")

        # Normaliser expires_at en datetime aware UTC
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        creds = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            client_id=settings.GMAIL_CLIENT_ID,
            client_secret=settings.GMAIL_CLIENT_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )

        # Rafraîchir si expiré ou inconnu
        now = datetime.now(timezone.utc)
        if expires_at is None or now >= expires_at:
            try:
                creds.refresh(Request())
            except Exception as e:
                raise Exception(f"Impossible de rafraîchir le token : {e}")

            # Sauvegarder TOUS les champs mis à jour
            self.gmail_collection.update_one(
                {"user_id": user_id},
                {"$set": {
                    "access_token": creds.token,
                    "refresh_token": creds.refresh_token or refresh_token,   # ← ne pas oublier
                    "expires_at": creds.expiry,
                    "updated_at": datetime.now(timezone.utc)
                }}
            )

        service = build('gmail', 'v1', credentials=creds)
        return service
    
    def handle_token_error(user_id):
        # Supprimer ou marquer comme non connecté
        self.gmail_collection.update_one(
            {"user_id": user_id},
            {"$set": {"connected": False}}
        )
        # Générer une nouvelle URL d'autorisation
        auth_url, state = get_gmail_auth_url(user_id)
        return auth_url, state
            
gmail_service = GmailServices()


from rest_framework.exceptions import APIException
from rest_framework import status

class GmailNotConnectedException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Utilisateur non connecté à Gmail"
    default_code = "gmail_not_connected"
            
# ===================================================================================================================
# Views inscirption dans  outlook
# class OutlookConfServices:
#     def save_conf()
# outlook_conf_service = OutlookConfServices()