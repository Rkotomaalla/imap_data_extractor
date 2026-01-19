from django.shortcuts import render
import logging
from rest_framework import viewsets, status
from django.conf import settings
from .serializer import MailSerializer
from .services import mail_service
from rest_framework.response import Response

from datetime import datetime
from imap_data_extractor_api.utils  import get_next_sequence_value, serialize_mongo_doc
from bots.permissions import IsBot
from rest_framework.permissions import IsAuthenticated, AllowAny
from bots.authentication import BotJWTAuthentication
from authentication.authentication import CustomJWTAuthentication
from configurations.services import mongo_service
from authentication.permissions import IsAdmin
from rest_framework.decorators import action
from .serializer import EmailFilterSerializer , EmailListSerializer

# Create your views here.
logger=logging.getLogger(__name__)

class MailViewSet(viewsets.ViewSet):
    """ViewSet Crud des email avec pymongo"""
    # authentication_classes = [BotJWTAuthentication]
    # permission_classes = [IsBot]
    # Creation des permission des Bots
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection('filtered_emails')
    
    def get_permissions(self):
        """Permissions différentes selon l'action"""
        if self.request.method == 'GET':
            return [IsAdmin()]
        elif self.request.method == 'POST':
            return [IsBot()]
        return [IsAuthenticated()]
    
    def get_authenticators(self):
        """Authentication différente selon l'action"""
        if self.request.method == 'GET':
            return [CustomJWTAuthentication()]
        elif self.request.method == 'POST':
            return [BotJWTAuthentication()]
        return [CustomJWTAuthentication()]
    
    def list(self,request):
        """GET /page"""
        # self.authentication_classes = [CustomJWTAuthentication]
        # self.permission_classes = [IsAdmin]
        try:
            ESSENTIAL_FIELDS = {
                "_id": 0,
               "gmail_message_id" : 1,
                "subject" : 1,
                "from" : 1,
                "received_at" : 1,
                "date" : 1,
                "has_attachment" : 1
            }
            # Recuperation avec pagination
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            skip = (page - 1) * page_size
            
            #filtres
            serializer = EmailFilterSerializer(data = request.query_params)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            filter_data=serializer.validated_data
            filter_data = {k: v for k, v in filter_data.items() if v is not None}
            total =  self.collection.count_documents(filter_data)
            emails =  list(
                self.collection
                        .find(filter_data,ESSENTIAL_FIELDS)
                        .skip(skip)
                        .limit(page_size)
            )

             #Serialization des Donnes trouves
            emails_data  = [serialize_mongo_doc(email) for email in emails]
            
            # serializer = EmailListSerializer(emails_data, many = True)                                        
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': emails_data
            })
        except Exception as e:  
            return Response(
                {'error' :  f'Erreur lors de la recuperation des email: {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def retrieve(self, request, pk=None):
        """
        GET /mail/{id}/
        Récupère un email par son gmail_message_id
        """
        try:
            if not pk:
                return Response(
                    {"detail": "L'identifiant de l'email est requis."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            data = mail_service.get_mail_id(pk)
            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la récupération de l'email: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        