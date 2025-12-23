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
from .serializer import EmailFilterSerializer
# Create your views here.
logger=logging.getLogger(__name__)

class MailViewSet(viewsets.ViewSet):
    """ViewSet Crud des email avec pymongo"""
    authentication_classes = [BotJWTAuthentication]
    permission_classes = [IsBot]
    # Creation des permission des Bots
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection('mail')
    
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
    

    @action(detail = False, methods = ['get'],authentication_classes = [CustomJWTAuthentication] , permission_classes=[IsAdmin])
    def list_email(self,request):
        """GET /page"""
        try:
            # Recuperation avec pagination
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            skip = (page - 1) * page_size
            
            #filtres
            serializer = EmailFilterSerializer(data = request.query_params)
            if serializer.is_valid:
                
        except Exception as e:
            return Response(
                {'error' :  f'Erreur lors de la recuperation des email: {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    