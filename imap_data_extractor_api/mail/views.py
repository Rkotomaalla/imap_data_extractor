from django.shortcuts import render
import logging
from rest_framework import viewsets, status
from django.conf import settings
from .serializer import MailSerializer
from rest_framework.response import Response

from datetime import datetime
from .utils import get_next_sequence_value, serialize_mongo_doc
from bots.permissions import IsBot
# Create your views here.
logger=logging.getLogger(__name__)

class MailViewSet(viewsets.ViewSet):
    """ViewSet Crud des email avec pymongo"""
    permission_classes = [IsBot]
    # Creation des permission des Bots
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = settings.MONGO_COLLECTIONS['mails']
        
    # def get_permissions(self):
    #     if self.action == 'create':  # Seulement pour create()
    #         return [IsBot()]
    #     return super().get_permissions()  # Autres actions gardent les permissions globales
    # def get_permissions(self):
    #     print(f"==================================================\nEto Tsika zao\n==================================================\n")     
    #     # self.action est défini par DRF (create, list, retrieve, ...)
    #     if getattr(self, 'action', None) == 'create':
    #         return [IsBot()]   # Seule la méthode create() exige IsBot
    #     # Pour les autres actions, tu peux retourner d'autres permissions ou []:
    #     from rest_framework.permissions import IsAuthenticated
    #     return [IsAuthenticated()]
    
    def create(self,request):
        serializers=MailSerializer(data=request.data)
         
        if serializers.is_valid():
            try:
                mail_data=serializers.validated_data
                mail_data['saved_date']=datetime.utcnow()
                mail_data['mail_id']= get_next_sequence_value('mail_id')
                
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