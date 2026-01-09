from django.shortcuts import render
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
# Create your views here.
class MailIntegratioinView(ViewSet):
    
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
                for record in history_response["history"]:
                    for msg in record.get("messages", []):
                        message_id = msg.get("id")
                        print("Nouveau message ID:", message_id)
                        process_gmail_message.delay(user_id=user_id, message_id=message_id)

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
            tokens =gmail_service.exchange_code_for_token(code, state)
            
            # Stockage dans MongoDB
            gmail_collection = mongo_service.get_collection('gmail_token')
            gmail_collection.update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "user_id": user_id,
                        "access_token": tokens["access_token"],
                        "refresh_token": tokens["refresh_token"],
                        "expires_at": tokens["expires_at"],
                        "connected": True,
                        "updated_at": datetime.utcnow()
                    }
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
            return HttpResponseRedirect("http://localhost:3000/outlook-success")
        
        except Exception as e:
            return Response(
                {"error": f"Erreur lors du callback Gmail: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )