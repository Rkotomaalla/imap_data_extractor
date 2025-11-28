from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializer import FieldSerializer,OperatorSerializer
from django.conf import settings
import logging
from rest_framework.decorators import action

from bots.utils import serialize_mongo_doc
logger=logging.getLogger(__name__)
# Create your views here.



class FieldViewSet(viewsets.ViewSet):
    """View pour les Fields"""
    permission_classes = [IsAuthenticated]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.collection = settings.MONGO_COLLECTIONS['fields']   
        self.operator_collection =  settings.MONGO_COLLECTIONS['operators']
    
    def list(self,request):
        """GET /api/fields/ - Liste tous les fields de l'utilisateur connecté"""
        try:             
                         # Récupération avec pagination
            page = request.query_params.get('page')
            page_size =request.query_params.get('page_size')


            total =  self.collection.count_documents({})
            
            if page and page_size: 
                page=int(page)
                page_size=int(page_size)
                            
                skip = (page - 1) * page_size
                fields =   list(self. collection.find().skip(skip).limit(page_size))
            
            else:
                fields =   list(self. collection.find())
                
            fields_data= [serialize_mongo_doc(field) for field in fields]
            serializer_data=FieldSerializer(fields_data,many = True)
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': serializer_data.data
            })
            
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la récupération: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail = True , methods = ['get'])
    def operator(self, request, pk=None):
        """
        Récupère tous les operators liés à un Field donné
        URL: /api/field/{pk}/operator/
        """
        try:
            # Vérifier que le  existe
            filters = {'field_id': int(pk)}
            total = self.operator_collection.count_documents(filters)
            
            operators =list(self.operator_collection.find(filters))
            operators_data = [serialize_mongo_doc(operator) for operator in operators]
            serializer_data = OperatorSerializer(operators_data, many=True)
            return Response({
                'count': total,
                'results': serializer_data.data
            })
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la récupération: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
                