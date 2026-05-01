from django.shortcuts import render
from django.conf import settings
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .services import gmail_service
from rest_framework.permissions import AllowAny
from django.http import HttpResponseRedirect
from configurations.services import mongo_service
from datetime import datetime
from django.http import HttpResponse
import json
import base64
import json as json_std
from .tasks import process_gmail_message  # tâche Celery à créer

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from rest_framework.decorators import action
from rest_framework.response import Response

# Create your views here.
class MailIntegrationView(ViewSet):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gmail_collection = mongo_service.get_collection("gmail_token")
        self.bots_collection = mongo_service.get_collection("bot")
    
    @action(detail=False, methods=["POST"], url_path="webhook", permission_classes=[AllowAny]) 
    def gmail_webhook(self, request):
        """
        Reçoit les notifications push Pub/Sub et traite les nouveaux mails
        """
        try: 
            body = json.loads(request.body)
            print(f"4______________________________________________________________________\nnotofications\n______________________________________________________________________\n")
            
            # Les notifications Gmail sont dans "message.data" encodé en base64
            notification = body.get("message")
            
            if not notification:
                return HttpResponse(status=204)
            
            data_b64 = notification.get("data")
            
            if not data_b64:
                print(f"4______________________________________________________________________\nif not data_b64\n______________________________________________________________________\n")
                return HttpResponse(status=204)
            
            data_json = json_std.loads(base64.b64decode(data_b64).decode("utf-8"))
            print(f"Données décodées : {data_json}")
            gmail_user_id = data_json.get("emailAddress")
            history_id=data_json.get("historyId")

            user_doc = self.gmail_collection.find_one({"gmail_email": gmail_user_id})
            if not user_doc:
                print(f"4______________________________________________________________________\nnot user_doc\n______________________________________________________________________\n")
                return HttpResponse(status=204)
            print(f"5______________________________________________________________________\nazo ilay mail\n______________________________________________________________________\n")
            
            user_id = user_doc.get("user_id")
            service = gmail_service.get_gmail_service(user_id)
            history_response = service.users().history().list(
                userId='me',
                startHistoryId=user_doc.get("prev_history_id"),
                historyTypes=['messageAdded']
            ).execute()

            # history_response peut ne pas avoir de "history"
            if "history" not in history_response:
                print("Aucun nouveau message depuis lastHistoryId")
            else:
                print(f"📧 {len(history_response['history'])} changements détectés")
                for record in history_response["history"]:
                    # ✅ CORRECTION : Utiliser messagesAdded au lieu de messages
                    messages_added = record.get("messagesAdded", [])
                    
                    for msg_added in messages_added:
                        message = msg_added.get("message", {})
                        message_id = message.get("id")
                        
                        # Vérifier que c'est bien dans INBOX
                        label_ids = message.get("labelIds", [])
                        
                        if message_id and "INBOX" in label_ids:
                            print(f"✅ Nouveau message INBOX détecté : {message_id}")
                            process_gmail_message.delay(user_id=user_id, message_id=message_id)
                        else:
                            print(f"⏭️ Message {message_id} ignoré (pas dans INBOX)")

            self.gmail_collection.update_one(
                    {"user_id": user_id},
                    {"$set": {
                        "prev_history_id" : history_id 
                    }}
                )
            return HttpResponse(status=200)  # Accepté, on ne veut pas de retry automatique pour les erreurs
        except Exception as e:
            print(f"Erreur webhook Gmail: {str(e)}")
            return HttpResponse(status=200)
        
        
        
    @action(detail=False, methods=['get'], url_path='start',permission_classes = [IsAuthenticated])
    def start_gmail_auth(self, request):
        """
        Génère l'URL OAuth Gmail et renvoie au front-end
        """
        try:
            user_id = request.user.uid_number
            if not user_id:
                return Response({"error": "Utilisateur non authentifié"}, status=status.HTTP_401_UNAUTHORIZED)
            
            auth_url, state = gmail_service.get_gmail_auth_url(user_id)
            request.session['gmail_oauth_state'] = state
            return Response({"auth_url": auth_url}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la génération de l'URL OAuth: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(detail=False, methods=['get'], url_path='callback',permission_classes=[AllowAny])
    def gmail_callback(self, request):
        """
        Récupère le code OAuth et stocke les tokens dans MongoDB
        """
        try:
            code = request.GET.get('code')
            state = request.GET.get('state')
            error = request.GET.get('error')
            
            if error or not code:
                return HttpResponseRedirect("http://localhost:3000/outlook-error?msg=auth_failed")
            
            if not state or not state.startswith("user_"):
                return HttpResponseRedirect("http://localhost:3000/outlook-error?msg=invalid_state")
            
            user_id = int(state.split("_")[1])
            # Échanger le code contre tokens
            tokens = gmail_service.exchange_code_for_token(code, state)
            
            # Stockage dans MongoDB
            gmail_collection = mongo_service.get_collection('gmail_token')
            
            updated_fields = {
                "user_id": user_id,
                "access_token": tokens["access_token"],
                "expires_at": tokens["expires_at"],
                "connected": True,
                "updated_at": datetime.utcnow()
            }
            # N'écraser le refresh_token QUE s'il est présent dans la réponse Google
            if tokens.get("refresh_token"):
                updated_fields["refresh_token"] = tokens["refresh_token"]
                
            gmail_collection.update_one(
                {"user_id": user_id},
                {
                    "$set": updated_fields       
                },
                upsert=True
            )
            # --- Récupérer l'adresse Gmail de l'utilisateur ---
            service = gmail_service.get_gmail_service(user_id)
            profile = service.users().getProfile(userId='me').execute()
            gmail_email = profile.get("emailAddress")  # ex: "krakotomalala0@gmail.com"

            # Ajouter gmail_email dans MongoDB
            gmail_collection.update_one(
                {"user_id": user_id},
                {"$set": {"gmail_email": gmail_email}}
            )
        # --- Fin récupération email ---
            # Redirection vers le frontend succès
            # Après avoir stocké les tokens, enregistre le webhook
            # Après avoir stocké les tokens et l'email
            response = self.register_gmail_webhook(user_id)
            if response.status_code != 200:
                print(f"Erreur lors de l'enregistrement du webhook: {response.data}")

            # Redirige vers le frontend succès
            return HttpResponseRedirect("http://localhost:3001/management/bot/list")
            
        except Exception as e:
            return Response(
                {"error": f"Erreur lors du callback Gmail: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
        
    def register_gmail_webhook(self, user_id):
        """
        Active la surveillance Gmail pour un utilisateur (Gmail Watch).
        """
        try:
            # Récupère les informations de l'utilisateur dans MongoDB
            user_doc = self.gmail_collection.find_one({"user_id": user_id})
            if not user_doc:
                return Response(
                    {"error": "Utilisateur non trouvé dans la base de données."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Crée les credentials OAuth 2.0
            creds = Credentials(
                token=user_doc["access_token"],
                refresh_token=user_doc["refresh_token"],
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.GMAIL_CLIENT_ID,
                client_secret=settings.GMAIL_CLIENT_SECRET,
                scopes=["https://www.googleapis.com/auth/gmail.readonly"]
            )

            # Crée le service Gmail
            service = build('gmail', 'v1', credentials=creds)

            # Corps de la requête pour activer le watch
            request_body = {
                'labelIds': ['INBOX'],
                'topicName': f'projects/{settings.GMAIL_PROJECT_ID}/topics/new_email_notification',
            }

            # Active la surveillance Gmail
            response = service.users().watch(userId='me', body=request_body).execute()

            # Stocke l'ID du watch et l'expiration dans MongoDB
            self.gmail_collection.update_one(
                {"user_id": user_id},
                {"$set": {
                    "prev_history_id": int(response["historyId"]),
                    "watch_expiration": response.get("expiration")
                }}
            )

            return Response(
                {
                    "message": "Surveillance Gmail activée avec succès.",
                    "historyId": response["historyId"],
                    "expiration": response.get("expiration")
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": f"Erreur lors de l'activation de la surveillance: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
            
# ===================================================================================================================
# Views inscirption dans  outlook
from .serializer import OutlookConfSerializer
from imap_data_extractor_api.utils import get_next_sequence_value
from imap_data_extractor_api.utils import serialize_mongo_doc

class OutlookIntegration(ViewSet):
    # izay olona authentifié rehetra dia afaka manketo
    permission_classes = [IsAuthenticated]
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # afake ovaina ilay nom de collection fa tsy voatery io 
        self.outlook_conf_collection = mongo_service.get_collection("outlook_conf")
        
    def create(self,request):
        serializer = OutlookConfSerializer(data = request.data)
        
        if serializer.is_valid():
            try:
                now =  datetime.utcnow()
                config_data = serializer.validated_data
                config_data["created_date"] = now
                config_data["updated_date"] = now
                config_data["user_id"] = request.user.uid_number
                config_data["conf_id"] = get_next_sequence_value("conf_id")
                
                result =  self.outlook_conf_collection.insert_one(config_data)
                
                created_config = self.outlook_conf_collection.find_one({'_id' : result.inserted_id})
                created_config = serialize_mongo_doc(created_config)
                
                response_serializer = OutlookConfSerializer(created_config)
                return Response(
                    
                    response_serializer.data,
                    status = status.HTTP_201_CREATED
                )
                
            except Exception as e:
                return Response(
                    {'error': f'Erreur lors de la création: {str(e)}'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    @action(detail=False, methods=["put"], url_path="outlook_conf")
    def update_config(self, request):
        """
        Modification complète (PUT)
        pk = conf_id
        """

        try:
            
            user_id = request.user.uid_number
            # Vérifier que la config existe et appartient à l'utilisateur
            existing_config = self.outlook_conf_collection.find_one({
                "user_id": request.user.uid_number
            })

            if not existing_config:
                return Response(
                    {"error": "Configuration introuvable"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = OutlookConfSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            update_data = serializer.validated_data
            update_data["updated_date"] = datetime.utcnow()

            self.outlook_conf_collection.update_one(
                {"user_id": user_id},
                {"$set": update_data}
            )

            updated_config = self.outlook_conf_collection.find_one({
                "user_id": request.user.uid_number
            })

            updated_config = serialize_mongo_doc(updated_config)

            return Response(
                OutlookConfSerializer(updated_config).data,
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la modification: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=["get"], url_path="outlook_conf")
    def retrieve_by_user(self, request):
        try:
            user_id = request.user.uid_number

            config = self.outlook_conf_collection.find_one({
                "user_id": user_id
            })

            if not config:
                return Response(
                    {"error": "Configuration introuvable"},
                    status=status.HTTP_404_NOT_FOUND
                )

            config = serialize_mongo_doc(config)

            return Response(
                OutlookConfSerializer(config).data,
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )