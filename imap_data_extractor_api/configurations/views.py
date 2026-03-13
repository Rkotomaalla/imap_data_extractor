from django.shortcuts import render
from rest_framework import viewsets, status
from django.conf import settings
from rest_framework.viewsets import ViewSet
from .services import mongo_service
from .serializers import MongoConfigSerializer
from django.utils import timezone
from rest_framework.response import Response
from authentication.permissions import IsAdmin
from rest_framework.permissions import AllowAny

from rest_framework.decorators import action
from imap_data_extractor_api.utils import serialize_mongo_doc , get_next_version_value
# Create your views here.
class MongoConfigViewSet(ViewSet):
    permission_classes=[IsAdmin]
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        

      
    def create(self, request):
        
        config= mongo_service.config
        
        serializer =   MongoConfigSerializer(config,  data=request.data , partial=True)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        data["updated_at"]=timezone.now()    
        data["config_id"] = get_next_version_value(mongo_service.version_collection,"mongo_config")
        data["version"] = data["config_id"]
        data['is_active'] =  True
        data['created_by'] = request.user.uid_number
        data['name'] = "default"
        
        try:
            # Tester la nouvelle configuration
            success = mongo_service.test_new_input_config(data)
            if not success:
                return Response(
                    {"error": "La configuration MongoDB est invalide ou la connexion a échoué."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Ajouter la configuration
            result = mongo_service.add_config(data)
            if not hasattr(result, 'inserted_id'):
                return Response(
                    {"error": "La configuration n'a pas pu être ajoutée."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Récupérer et sérialiser la configuration insérée
            inserted_config = mongo_service.config_collection.find_one({'_id': result.inserted_id})
            if not inserted_config:
                return Response(
                    {"error": "La configuration insérée n'a pas été trouvée."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            inserted_config = serialize_mongo_doc(inserted_config)
            response_serializer = MongoConfigSerializer(inserted_config)

            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": f"Une erreur inattendue est survenue : {e}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
            
    def get(self,request):
        try:
            # Récupérer et sérialiser la configuration insérée
            inserted_config = mongo_service.config_collection.find_one({'is_active': True})
            if not inserted_config:
                return Response(
                    {"error": "Aucune configuration de la base trouvée."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            inserted_config = serialize_mongo_doc(inserted_config)
            response_serializer = MongoConfigSerializer(inserted_config)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"error": f"Une erreur inattendue est survenue : {e}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    
        