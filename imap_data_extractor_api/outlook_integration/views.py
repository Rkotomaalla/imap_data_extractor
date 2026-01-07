from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
import logging
from rest_framework import viewsets, status
from rest_framework.decorators import action, renderer_classes  
from rest_framework.renderers import BaseRenderer
from rest_framework.viewsets import ViewSet
from django.conf import settings
import msal
from django.http import HttpResponseRedirect
from configurations.services import  mongo_service
from users.user_services import user_service
from datetime import datetime, timedelta
import hmac
import hashlib
import json
from .tasks import outlook_task
from urllib.parse import unquote
from django.views.decorators.csrf import csrf_exempt
# Create your views here.
logger  = logging.getLogger(__name__)

class PlainTextRenderer(BaseRenderer):
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        return data.encode('utf-8') if isinstance(data, str) else data

class OutlookIntegrationView(ViewSet):
    """
    Docstring for OutlookIntegrationView
    Génère l'URL d'autorisation Microsoft
    Appelée par React quand l'utilisateur clique "Connecter Outlook"
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.outlook_collection = mongo_service.get_collection('outlook_token')   
    
    @action(detail=False ,methods=['get'], url_path = "start" , permission_classes=[IsAuthenticated])
    def start_outlook_auth(self,request):
        #MSAL (confidential client = backend)
        app = msal.ConfidentialClientApplication(
            client_id = settings.AZURE_CLIENT_ID,
            client_credential=settings.AZURE_CLIENT_SECRET,
            authority=settings.AZURE_AUTHORITY
        )
        #scope necessaire
        # scopes = [
        #     "Mail.Read",
        #     "offline_access",
        # ]
        # Après :
        scopes = [
        "Mail.Read",
        "Mail.ReadBasic",   
        "Mail.ReadWrite"# Optionnel
        # "Subscriptions.ReadWrite"
        ]
        # Génération de l'URL d'autorisation
        auth_url = app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=settings.AZURE_REDIRECT_URI,  # ex: https://ton-domaine.com/api/outlook/callback/
            state=f"user_{request.user.uid_number}",  # Optionnel : pour sécurité et traçabilité
            prompt="consent"  # ← Très important : force l'écran de consentement + donne le refresh_token
        )
        # On renvoie juste l'URL au front-end
        return Response({
            "auth_url": auth_url
        }, status=status.HTTP_200_OK)
        
    @action(detail=False, methods=['get'],url_path = "callback", permission_classes=[AllowAny])
    def outlook_callback(self,request):
        try:
            code = request.GET.get('code')
            state = request.GET.get('state')
            error = request.GET.get('error')
            
            if error or not code:
                return HttpResponseRedirect("http://localhost:3000/outlook-error")

            if not state or not state.startswith("user_"):
                return HttpResponseRedirect("http://localhost:3000/outlook-error")
           
            state_user_id = state.split("_")[1]  # ex: "user_11003" → "11003"
            user = user_service.get_user_by_id(state_user_id)
            if not user:
                return HttpResponseRedirect("http://localhost:3000/outlook-error?msg=user_not_found")
            # Echange contre un token
            app = msal.ConfidentialClientApplication(
                client_id=settings.AZURE_CLIENT_ID,
                client_credential=settings.AZURE_CLIENT_SECRET,
                authority=settings.AZURE_AUTHORITY,
            )
            result = app.acquire_token_by_authorization_code(
                code=code,
                scopes=["https://graph.microsoft.com/Mail.Read"],
                redirect_uri=settings.AZURE_REDIRECT_URI,
            )
            if "error" in result:
                return HttpResponseRedirect(
                    f"http://localhost:3000/outlook-error?msg={result.get('error')}"
                )
            # Extraction des tokens
            access_token = result.get("access_token")
            refresh_token = result.get("refresh_token")
            expires_in = result.get("expires_in", 3599)  # ~1 heure
            
            # Calcul de l'expiration
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

            # Stockage ou mise à jour dans MongoDB
            self.outlook_collection.update_one(
                    {"user_id": user.get("uid_number")},  # ou user.uid_number selon ce que tu préfères
                    {
                        "$set": {
                            "user_id": user.get("uid_number"),
                            "username": user.get("username"),  # optionnel, pour debug
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "expires_at": expires_at,
                            "connected": True,
                            "updated_at": datetime.utcnow(),
                        }
                    },
                    upsert=True  # Crée le document s'il n'existe pas
            )
            return Response(
                {
                    "succes" : "callback reussi"
                },status=status.HTTP_201_CREATED
            )    
            # Redirection succès vers React
            # return HttpResponseRedirect("http://localhost:3000/outlook-success")
        except Exception as e :
            return Response(
                {
                    "error" : f"Erreur lors de la callback de l'outlook{str(e)}"
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )    
    
    # @action(detail = False, methods = ['GET', 'POST'], url_path = "webhook", permission_classes=[AllowAny])
    # def outlook_webhook(self,request):
    #     print(f" ato aloh zao   ====================================================")
    #     return Response(status=200)

    @action(detail = False,methods=['GET', 'POST'],url_path = "webhook", permission_classes=[AllowAny], renderer_classes=[PlainTextRenderer])
    def outlook_webhook(self, request):
        """
        Endpoint public appelé par Microsoft Graph à chaque nouveau mail
        """
        CLIENT_STATE_SECRET = "secret-client-state-123"
        
        # ================== 1. Validation initiale (GET ou POST avec validationToken) ==================
        validation_token = request.GET.get("validationToken")
        token_decoded = unquote(validation_token)

        print(f"=======================================\n{token_decoded}\n=======================================")
        
        if validation_token:
            # Microsoft vérifie l'URL → renvoie le token en texte brut
            return HttpResponse(validation_token, content_type="text/plain", status=200)

        # ================== 2. Vérification de sécurité (POST) =================s
        if request.method == "POST" : 
            try:
                # recuperation du  client state envoyé par miscrosoft
                body = json.loads(request.body)
                # tratement de chaque notification
                for notification in body.get("value",[]):
                    received_client_state = body.get("clientState")
                    if received_client_state != CLIENT_STATE_SECRET:
                        continue
                    
                    #on ne traite que les creation des messages 
                    if notification.get("changeType") != "created":
                        continue
                        
                    # Extraction des infos
                    subscription_id = notification.get("subscriptionId")
                    message_id = notification.get("resourceData", {}).get("id")
                    if not subscription_id or not message_id:
                        continue
                    
                    user_doc = self.outlook_collection.find_one({
                        "subscription_id": subscription_id
                    })
                    if user_doc:
                        user_id = user_doc["user_id"]
                        outlook_task.delay(user_id, message_id)  # Traitement async
                return HttpResponse(status=202)  
            except Exception as e:
                # Log l'erreur mais retourne 202 pour éviter les retry storms
                print(f"Erreur webhook Outlook: {e}")
                return HttpResponse(status=202)      
        return HttpResponse("Method not allowed" , status = 405)
