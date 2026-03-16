from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from imap_data_extractor_api.utils import serialize_mongo_doc
from configurations.services import mongo_service


# Create your views here.
class ActionViewSet(viewsets.ViewSet):
    permission_classes =  [IsAuthenticated]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection('actions')        
    
    def list(self, request):
        try:
            total = self.collection.count_documents({})
            action_data = list(self.collection.find({}))
            serialized_data = [serialize_mongo_doc(action) for action in action_data]
            return Response({
                'count' : total,
                'result' : serialized_data
            })
        except Exception as e:
            return Response(
                {'error':f'Erreur lors de la recuperation des actions : {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    