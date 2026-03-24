from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
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
                'success' : True,
                'count' : total,
                'results' : serialized_data
            },status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {   
                    'success' : False,
                    'error':f'Erreur lors de la recuperation des actions : {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(
    detail=True,
    methods=["get"],
    url_path="child",
    permission_classes=[IsAuthenticated]
    )
    def get_child_action(self, request, pk=None):
        """Recherche de la liste des sub actions"""
        try:
            action_id = int(pk)
            action = self.collection.find_one({"action_id": action_id})

            if not action:
                return Response(
                    {
                        'success': False,
                        'error': "L'id action non trouvé"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # Nettoyage Mongo
            action.pop("_id", None)

            child_ids = action.get('child_action', [])

            if not isinstance(child_ids, list):
                child_ids = []

            children = list(self.collection.find(
                {"action_id": {"$in": child_ids}},
                {"_id": 0, "action_id": 1, "action_label": 1}
            ))

            # Garder l’ordre
            children_map = {child["action_id"]: child for child in children}

            ordered_children = [
                children_map[child_id]
                for child_id in child_ids
                if child_id in children_map
            ]

            action["child_action"] = ordered_children

            return Response(action, status=status.HTTP_200_OK)

        except ValueError:
            return Response(
                {"detail": "L'identifiant doit être un entier"},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"detail": f"Erreur lors de la récupération : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
                