# gmail_services.py
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request    
import base64
import os
from django.conf import settings
from datetime import datetime
import logging
from configurations.services import mongo_service
from pymongo.errors import DuplicateKeyError
from imap_data_extractor_api.utils import get_next_sequence_value
logger = logging.getLogger(__name__)

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
    
    def save_email_and_attachments(self,service,user_id,message_id: int,mail_extracted_data: dict,attachment_extracted_data:dict)->bool:
        """
            Sauvegarde ATTACHMENT + MAIL => si echoue => ROLLBACK.
            Retourne True SI SUCCES, False sinon.
        """
        try:
            # sauvegrade Email
            try:
                saving_mail_result = self.save_email(mail_extracted_data)
                if not saving_mail_result:
                    logger.error(f"Echec sauvegarde email : {message_id}")
                    return False
            except Exception as e:
                logger.error(f"Exception save_email : {e}")
                return False
            if attachment_extracted_data:
                try:
                    saving_att_result = self.save_attachments(
                        service,user_id, message_id, attachment_extracted_data
                    )       
                    if not saving_att_result:
                        # rollback si attachments échouent
                        self.delete_email_rollback(message_id)
                        logger.error(
                            f"Rollback : échec insertion attachments pour email {message_id}"
                        )
                    return False
                except Exception as e:
                    # rollback sur exception
                    gmail_service.delete_email_rollback(message_id)
                    logger.error(
                        f"Rollback exception attachments email {message_id} : {e}"
                    )
                return False
        except Exception as e:
            # catch global pour éviter que la task Celery plante sans log
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
        
        
        
    def get_gmail_service(self, user_id):
        """Récupère le service Gmail pour un utilisateur, avec refresh automatique."""
        user_doc = self.gmail_collection.find_one({"user_id": user_id})
        if not user_doc:
            raise Exception("Utilisateur non connecté à Gmail")

        access_token = user_doc.get("access_token")
        refresh_token = user_doc.get("refresh_token")
        expires_at = user_doc.get("expires_at")

        # convertir expires_at si besoin
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        # Rafraîchir si nécessaire
        creds = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            client_id=settings.GMAIL_CLIENT_ID,
            client_secret=settings.GMAIL_CLIENT_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )

        if expires_at is None or datetime.utcnow() >= expires_at:
            if not refresh_token:
                raise Exception("Refresh token manquant, l'utilisateur doit réautoriser l'app")
            try:
                creds.refresh(Request())
            except Exception as e:
                raise Exception(f"Impossible de rafraîchir le token : {e}")

            # Mettre à jour MongoDB
            self.gmail_collection.update_one(
                {"user_id": user_id},
                {"$set": {
                    "access_token": creds.token,
                    "expires_at": creds.expiry,
                    "updated_at": datetime.utcnow()
                }}
            )

        service = build('gmail', 'v1', credentials=creds)
        return service

            
gmail_service = GmailServices()