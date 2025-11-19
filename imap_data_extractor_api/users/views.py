from django.shortcuts import render

# Create your views here.
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from  .user_services import user_service
from authentication.permissions import IsAdmin
from rest_framework.views import APIView

import logging
logger = logging.getLogger(__name__)

class UserLdapCreateView(APIView):
    """
    Vue pour créer un utilisateur dans OpenLDAP
    Accessible uniquement aux administrateurs
    """
    permission_classes = [IsAuthenticated, IsAdmin]
    
    def post(self, request):
        """
        Créer un nouvel utilisateur LDAP
        """
        
        serializer = UserSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': 'Données invalides',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        
        if user_service.user_exists(email):
            return Response({
                'success': False,
                'message': 'Un utilisateur avec cet email existe déjà'
            }, status=409)  # 409 Conflict
        try: 
            # # Appeler le service LDAP pour créer l'utilisateur
            result = user_service.add_user(serializer.validated_data)
            return Response({
                'success': True,
                'message': 'Utilisateur créé avec succès',
                'data': result
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            
            return Response({
                'success': False,
                'message': 'Erreur lors de la création de l\'utilisateur',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        