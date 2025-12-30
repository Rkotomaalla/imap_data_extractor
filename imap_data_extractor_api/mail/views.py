from django.shortcuts import render
import logging
from rest_framework import viewsets, status
from django.conf import settings
from .serializer import MailSerializer
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
        self.collection = mongo_service.get_collection('mail')
    
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
    
    def create(self,request):
        serializers=MailSerializer(data=request.data)
        if serializers.is_valid():
            try:
                mail_data=serializers.validated_data
                mail_data['saved_date']=datetime.utcnow()
                mail_data['mail_id']= get_next_sequence_value('mail_id')
                
                token = request.auth
                bot_id = getattr(token, 'payload', {}).get('bot_id', None)
                mail_data['bot_id'] = bot_id
                
                result = self.collection.insert_one(mail_data)
                created_data = self.collection.find_one({'_id': result.inserted_id})
                created_data = serialize_mongo_doc(created_data)
                response_serializer = MailSerializer(created_data)
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response(
                    {'error': f'Erreur lors de la création: {str(e)}'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def list(self,request):
        """GET /page"""
        # self.authentication_classes = [CustomJWTAuthentication]
        # self.permission_classes = [IsAdmin]
        try:
            ESSENTIAL_FIELDS = {
                "_id": 0,
               "mail_id" : 1,
                "subject" : 1,
                "from_name" : 1,
                "from_email" : 1,
                "received_date" : 1,
                "status" : 1,
                "is_unread" : 1,
                "has_attachment" : 1,
                "priority" : 1,
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
            # if filter_data["has_attachment"] is None:
            #     filter_data.pop('has_attachment', None)
            # if filter_data["received_date"] is None:
            #     filter_data.pop('received_date', None)
            # if filter_data["date"] is None:
            #     filter_data.pop('date', None)
            # if filter_data["status"] is None:
            #     filter_data.pop('status', None)
            # Nettoyer tous les champs None en une seule ligne
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
            
            serializer = EmailListSerializer(emails_data, many = True)                                        
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': serializer.data
            })
        except Exception as e:  
            return Response(
                {'error' :  f'Erreur lors de la recuperation des email: {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    