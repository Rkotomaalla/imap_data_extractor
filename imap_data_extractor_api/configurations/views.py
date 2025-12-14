from django.shortcuts import render
from rest_framework import viewsets, status
from django.conf import settings
from rest_framework.viewsets import ViewSet
from .services import mongo_service
from serializers import MongoConfigSerializer
from django.utils import timezone
from rest_framework.response import Response
from authentication.authentication import CustomJWTAuthentication
from authentication.permissions import IsAdmin
# Create your views here.
class MongoConfigViewSet(ViewSet):
    authentication_classes=[CustomJWTAuthentication]
    permission_classes=[IsAdmin]
    
    def partial_update(self, request, pk = None):
        config= mongo_service.config
        
        serializer =   MongoConfigSerializer(config,  data=request.data , partial=True)
        if serializer.is_valid():
            data = serializer.validated_data
            data["updated_at"]=timezone.now()    
            
            mongo_service.update_config(data)
            
            return Response({"detail" : 'Configuration mise à jours'} , status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
    
    def create(self, request ):
        