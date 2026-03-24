

# Create your views here.
from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from configurations.services import mongo_service
from rest_framework.response import Response

class DirectoryViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.collection = mongo_service.get_collection('directories')  # Nom de la collection en français (ou 'directories' en anglais)

    @action(
        detail=False,
        methods=["get"],
        url_path="main",
        permission_classes=[IsAuthenticated]
    )
    def get_main_repo(self, request):
        try:
            main_list = list(self.collection.find(
                {"parents_dir": None},
                {"_id": 0, "dir_id": 1, "dir_label": 1}  
            ))

            # Corrigé : main_list.length() → len(main_list)
            count = len(main_list)

            return Response({
                'success': True,
                'count': count,
                'results': main_list
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "error": f"Erreur lors de la récupération des dossiers: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(
        detail=True,
        methods=["get"],
        url_path="child",
        permission_classes=[IsAuthenticated]
    )
    def get_child_repo(self, request , pk = None):
        try:
            
            parent_id =  int(pk)
            directories = list(self.collection.find(
                {"parents_dir": parent_id},  # Filtre les répertoires dont parents_dir contient parent_id
                {"_id": 0, "dir_id": 1, "dir_label": 1, "parents_dir": 1}
            ))
            
            return Response({
                'success': True,
                'count': len(directories),
                'results': directories
            }, status=status.HTTP_200_OK)
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
    