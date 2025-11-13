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
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
        """ 
        API de login avec authentification LDAP et génération de JWT.
        
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
                "last_ldap_sync": "2025-11-13T10:30:00Z",
                "date_joined": "2025-11-13T09:00:00Z",
                "is_active": true
            },
            "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
            "expires_in": 900
        }
        
        Response 400 - Données invalides:
        {
            "success": false,
            "message": "Données invalides",
            "errors": {...}
        }
        
        Response 401 - Authentification échouée:
        {
            "success": false,
            "message": "Identifiants incorrects"
        }
        
        Response 403 - Compte désactivé:
        {
            "success": false,
            "message": "Compte désactivé"
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
        
        # Authentification via LDAP (utilise votre LDAPAuthenticationBackend)
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
        
        # Générer les tokens JWT
        refresh = RefreshToken.for_user(user)
        # Ajouter les claims personnalisés
        refresh['username'] = user.username
        refresh['email'] = user.email
        refresh['ldap_dn'] = user.ldap_dn if hasattr(user, 'ldap_dn') else ''
        
        # Rôles LDAP
        if hasattr(user, 'ldap_roles'):
            refresh['roles'] = [role.get('name') for role in user.ldap_roles]
        
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        logger.info(f"Connexion réussie pour: {username}")
    
        return Response({
        'success': True,
        'message': 'Connexion réussie',
        'user': UserSerializer(user).data,
        'access': access_token,
        'refresh': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 900  # 15 minutes en secondes
    }, status=status.HTTP_200_OK)
        
        
        
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    """
    Rafraîchit l'access token en utilisant le refresh token.
    
    POST /api/auth/refresh/
    
    Body:
    {
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    
    Response 200:
    {
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Nouveau si ROTATE_REFRESH_TOKENS=True
    }
    """
    from rest_framework_simplejwt.views import TokenRefreshView
    return TokenRefreshView.as_view()(request._request)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    Déconnecte l'utilisateur et blacklist le refresh token.
    
    Endpoint: POST /api/auth/logout/
    
    Headers requis:
        Authorization: Bearer <access_token>
    
    Body (optionnel):
    {
        "refresh": "<refresh_token>"
    }
    
    Response 200:
    {
        "success": true,
        "message": "Déconnexion réussie",
        "username": "jdupont"
    }
    """
    username = request.user.username
    logger.info(f"Tentative de déconnexion JWT pour: {username}")
    try:
        # Recuperer le refresh token depuis le body 
        refresh_token = request.data.get('refresh')
        
        if refresh_token:
            try:
            # Blacklist le refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
                logger.info(f"Refresh token blacklisté pour: {username}")
            except Exception as e:
                logger.warning("Erreur lors du blacklist du refresh token: {e}")
                
        # Déconnexion de la session Django (si utilisée en parallèle)
        logout(request)
        
        logger.info(f"Déconnexion JWT réussie pour: {username}")
        
        return Response({
            'success': True,
            'message': 'Déconnexion réussie',
            'username': username
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Erreur lors de la déconnexion JWT de {username}: {str(e)}", exc_info=True)
        
        return Response({
            'success': False,
            'message': 'Erreur lors de la déconnexion',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def  current_user_view(request):
    """
    Récupère les informations de l'utilisateur connecté via JWT.
    
    GET /api/auth/me/
    
    Headers:
        Authorization: Bearer <access_token>
    
    Response 200:
    {
        "id": 1,
        "username": "jdupont",
        "email": "jdupont@entreprise.local",
        ...
    }
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)