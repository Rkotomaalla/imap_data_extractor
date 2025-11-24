from django.shortcuts import render

# Create your views here.
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer,UserUpdateSerializer
from  .user_services import user_service
from authentication.permissions import IsAdmin
from rest_framework.views import APIView

import logging
logger = logging.getLogger(__name__)


# Class CRUD pour les URL ====>>> "/users/"
class UserLdapView(APIView):
    """
    Vue pour créer un utilisateur dans OpenLDAP
    Accessible uniquement aux administrateurs
    """
# attribution des permissions pour la class pour chaque methodes
    # def get_permissions(self):
    #     if self.request.method == 'POST' or  self.request.method=='GET':
    #         return [IsAuthenticated(), IsAdmin()]
    #     return  [IsAuthenticated()]
    permission_classes_by_method = {
    'GET': [IsAuthenticated()],
    'POST': [IsAuthenticated(), IsAdmin()],
    'PUT': [IsAuthenticated(), IsAdmin()],
    'DELETE': [IsAuthenticated(), IsAdmin()],
    }

    def get_permissions(self):
        return self.permission_classes_by_method.get(
            self.request.method,
            [IsAuthenticated()]  # default
        )
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
            if not user_service.set_user_role_posix_group(result):
                user_service.delete_user(result['uid_number'])
                return Response({
                        'success': False,
                        'message': 'Erreur lors de l\'attribution du rôle à l\'utilisateur'
                }, status=409)  # 409 Conflict
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
        
    def get(self, request):
        """
        Lister tous les utilisateurs depuis LDAP
        """
        try:
            users=user_service.list_users()
            return Response({
                'success': True,
                'count': len(users),
                'data': users
            })
        
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
      
# class Crud pour les URL====> "/users/id"   
class UserLdapDetailView(APIView):
    """
    Vue pour récupérer les détails d'un utilisateur LDAP
    Accessible uniquement aux administrateurs
    """
    # def get_permissions(self):
    #     if self.request.method=='DELETE':
    #         return  [IsAuthenticated(),IsAdmin()]
    #     return  [IsAuthenticated()] 
    
    permission_classes_by_method = {
    'GET': [IsAuthenticated()],
    'POST': [IsAuthenticated(), IsAdmin()],
    'PUT': [IsAuthenticated(), IsAdmin()],
    'DELETE': [IsAuthenticated(), IsAdmin()],
    }

    def get_permissions(self):
        return self.permission_classes_by_method.get(
            self.request.method,
            [IsAuthenticated()]  # default
        )
    def get(self, request, user_id):
        """
        Récupérer les détails d'un utilisateur LDAP par son nom d'utilisateur
        """
        try:
            user = user_service.get_user_by_id(user_id)
            
            if not user:
                return Response({
                    'success': False,
                    'message': 'Utilisateur non trouvé'
                }, status=status.HTTP_404_NOT_FOUND)
            return Response({
                'success': True,
                'data': user
            })
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e),
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
    def delete(self, request, user_id):
        """
        Supprimer un utilisateur LDAP par son nom d'utilisateur
        """
        try:
            success = user_service.delete_user(user_id)
            
            if not success:
                return Response({
                    'success': False,
                    'message': 'Utilisateur non trouvé ou erreur lors de la suppression'
                }, status=status.HTTP_404_NOT_FOUND)
            
            return Response({
                'success': True,
                'message': 'Utilisateur supprimé avec succès'
            })
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e),
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    def put(self,request,user_id):
        """
            modification des Utilisateurs
        """
        serializer=UserUpdateSerializer(data=request.data)
        if not serializer.is_valid():
         return Response({
                'success': False,
                'message': 'Données invalides',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        
        email = serializer.validated_data.get('email')
        if email :
            if user_service.user_exists(email):
                return Response({
                    'success': False,
                    'message': 'Un utilisateur avec cet email existe déjà'
                }, status=409)  # 409 Conflict
            
            
        try: 
            # # Appeler le service LDAP pour créer l'utilisateur
            result = user_service.update_user(serializer.validated_data,user_id,True)
            
            return Response({
                'success': True,
                'message': 'Utilisateur mis à jour avec succès',
                'data': result
            })
        except Exception as e:
             return Response({
                'success': False,
                'message': str(e),
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)