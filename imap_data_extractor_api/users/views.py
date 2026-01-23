from django.shortcuts import render
from imap_data_extractor_api.utils  import get_next_sequence_value, serialize_mongo_doc
from configurations.services import  mongo_service

# Create your views here.
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer,UserUpdateSerializer
from  .user_services import user_service
from authentication.permissions import IsAdmin
from rest_framework.views import APIView
from rest_framework.decorators import action
from mail.serializer import EmailFilterSerializer
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
    'PUT': [IsAuthenticated()],
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
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size
            
            role = request.query_params.get('role') or None
            departement =request.query_params.get('departement') or None
            print(f"role={role}, departement = {departement}")
            users=user_service.list_users(role,departement)
            paginated_users = users[skip:skip + page_size]  # Sous-liste pour la page demandée
            return Response({
                'success': True,
                'count': len(users),
                'data': paginated_users
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
    'PUT': [IsAuthenticated()],
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

            is_admin = (request.user.ldap_role == "admin")
            result = user_service.update_user(serializer.validated_data,user_id,is_admin)
            
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
             
class UserMailView(APIView):
    permission_classes = [IsAuthenticated]
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.collection = mongo_service.get_collection('filtered_emails')   
    def get(self,request, pk=None):
        """
        Docstring for get_user_mail
        GET users/{pk}/mail
        """
        try:
            
            try:
                user_id = int(pk)
            except (TypeError, ValueError):
                return Response({"detail": "L'identifiant de l'utilisateur doit être un entier"}, status=status.HTTP_400_BAD_REQUEST)
                
            ESSENTIAL_FIELDS = {
                "_id": 0,
               "gmail_message_id" : 1,
                "subject" : 1,
                "from" : 1,
                "received_at" : 1,
                "date" : 1,
                "has_attachment" : 1
            }
            
            # Recuperation avec pagination
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size
                
            #filtres
            serializer = EmailFilterSerializer(data = request.query_params)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            filter_data=serializer.validated_data
            
            filter_data["user_id"] = user_id
            filter_data = {k: v for k, v in filter_data.items() if v is not None}
            
            total =  self.collection.count_documents(filter_data)
            emails =  list(
                self.collection
                        .find(filter_data,ESSENTIAL_FIELDS)
                        .skip(skip)
                        .limit(page_size)
            )
            #Serialization des Donnes trouves
            emails_data  = [serialize_mongo_doc(email) for email in emails]
            # serializer = EmailListSerializer(emails_data, many = True)                                        
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': emails_data
            })
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