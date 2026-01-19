from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializer import FieldsSerializer,OperatorSerializer
from django.conf import settings
import logging
from rest_framework.decorators import action

from imap_data_extractor_api.utils import serialize_mongo_doc

from configurations.services import mongo_service
logger=logging.getLogger(__name__)
# Create your views here.



class FieldViewSet(viewsets.ViewSet):
    """View pour les Fields"""
    permission_classes = [IsAuthenticated]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.fields_collection = mongo_service.get_collection('fields')   
        self.operator_collection =  mongo_service.get_collection('operators')
    
    def list(self,request):
        """GET /api/fields/ - Listet ous les fields de l'utilisateur connecté"""
        try:             
                         # Récupération avec pagination
            page = request.query_params.get('page')
            page_size =request.query_params.get('page_size')


            total =  self.fields_collection.count_documents({})
            
            if page and page_size: 
                page=int(page)
                page_size=int(page_size)
                            
                skip = (page - 1) * page_size
                fields =   list(self. fields_collection.find(
                        {},
                        {"_id":0 , "field_id" : 1 , "field_name" : 1,"description":1,"is_indexed": 1}
                    ).skip(skip).limit(page_size))
            
            else:
                fields =   list(self. fields_collection.find(
                    {},
                    {"_id":0 , "field_id" : 1 , "field_name" : 1,"description":1,"is_indexed": 1}
                ))
                
            fields_data= [serialize_mongo_doc(field) for field in fields]
            
            serializer_data=fields_data
            
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': serializer_data
            })
            
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la récupération: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    
    
    
    @action(
        detail=True,
        methods=["get"],
        url_path ="operators",
        permission_classes=[IsAuthenticated]
    )    
    def get_fieds_operators(self,request,pk=None):
        """recherche operators per id Fields"""
        try:
            field_id  =  int(pk)
            fields_doc = self.fields_collection.find_one(
                {"field_id": field_id},
                {"_id": 0, "field_id" : 1 , "operators" :  1}
            )
            if not fields_doc:
                return Response(
                    {"detail" : f"L'id  field {field_id} invalide"},
                    status=status.HTTP_404_NOT_FOUND
                )
            operators_ids = fields_doc.get("operators", [])
            
            if not operators_ids:
                return Response(
                    {"detail" : f"Le field_id {field_id} ne possede aucun operateur"},
                    status=status.HTTP_404_NOT_FOUND
                )
                
            results = []
            missing_ids = []
            
            for operator_id in operators_ids:
                operator_doc = self.operator_collection.find_one(
                    {"operator_id": operator_id},
                    {"_id": 0, "operator_id": 1, "description": 1}
                )

                if operator_doc:
                    results.append(operator_doc)
                else:
                    missing_ids.append(operator_id)
            return Response(
                {
                    "count": len(results),
                    "missing operator ids" :  missing_ids,
                    "results": results
                },
                status=status.HTTP_200_OK
            )
            
        except ValueError:
            return Response(
                {"detail": "L'identifiant du field doit être un entier"},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"detail": f"Erreur lors de la récupération : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
                    