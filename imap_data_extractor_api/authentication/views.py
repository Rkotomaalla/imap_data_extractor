from django.shortcuts import render

# Create your views here.
import logging
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from .serializers import LoginSerializer, UserSerializer, LoginResponseSerializer
from .services.ldap_service import LDAPService


logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
        """
        API de login avec authentification LDAP.
        
        POST /api/auth/login/
        Body:
        {
            "username": "jdupont",
            "password": "password123"
        }
        
        Response 200:
        {
            "success": true,
            "message": "Connexion réussie",
            "user": {
                "id": 1,
                "username": "jdupont",
                "email": "jdupont@entreprise.local",
                "first_name": "Jean",
                "last_name": "Dupont",
                "ldap_dn": "uid=jdupont,ou=users,dc=entreprise,dc=local",
                "roles": [{"name": "admin", "description": "Administrateurs"}],
                "last_ldap_sync": "2025-11-12T10:30:00Z",
                "date_joined": "2025-11-12T09:00:00Z",
                "is_active": true
            },
            "session_id": "abc123xyz"
        }
        
        """
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"Données de login invalides: {serializer.errors}")
            return Response({
                'success': False,
                'message': 'Données invalides',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Authentification via LDAP
        user = authenticate(request, username=username, password=password)
        
        if user is None:
            logger.warning(f"Échec de connexion pour: {username}")
            return Response({
                'success': False,
                'message': 'Identifiants incorrects'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_active:
            logger.warning(f"Compte désactivé: {username}")
            return Response({
                'success': False,
                'message': 'Compte désactivé'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Créer la session Django
        login(request, user)
            
        logger.info(f"Connexion réussie pour: {username}")
    
        return Response({
            'success': True,
            'message': 'Connexion réussie',
            'user': UserSerializer(user).data,
            'session_id': request.session.session_key
        }, status=status.HTTP_200_OK)
        
        
        