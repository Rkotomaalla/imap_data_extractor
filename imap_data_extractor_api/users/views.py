from django.shortcuts import render
from imap_data_extractor_api.utils  import get_next_sequence_value, serialize_mongo_doc
from configurations.services import  mongo_service
from datetime import datetime
# Create your views here.
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated , AllowAny
from .serializers import UserSerializer,UserUpdateSerializer
from  .user_services import user_service
from authentication.permissions import IsAdmin
from rest_framework.views import APIView
from rest_framework.decorators import action
from mail.serializer import EmailFilterSerializer
from authentication.services.ldap_service import LDAPService
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
            
            print(request.query_params)
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size
            
            role = request.query_params.get('role') or None
            departement =request.query_params.get('departement') or None
            email =request.query_params.get('email') or None
            cn =request.query_params.get('name') or None
            
            users=user_service.list_users(role, departement, email, cn)
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
            
            
    # def delete(self, request, user_id):
    #     """
    #     Supprimer un utilisateur LDAP par son nom d'utilisateur
    #     """
    #     try:
    #         motif  = request.query_params.get("motif")
    #         user_uid = request.user.uid_number
    #         if not motif:
    #             return Response(
    #                 {
    #                     'message' : 'Motif obligatoire.',
    #                     'success' : False
    #                 },
    #                 status = status.HTTP_400_BAD_REQUEST
    #             )
                
    #         bot_collection = mongo_service.get_collection('bot')
            
    #         filter = {'assigned_user_id': user_id}            
    #         active_bots = list(bot_collection.find(filter, {'_id': 0, 'bot_id': 1}))
    #         if active_bots:
    #             bot_ids = [bot['bot_id'] for bot in active_bots]
    #             return Response({
    #                 'success': False,
    #                 'message': "Impossible de supprimer l'utilisateur : l'utilisateur possedes encore de bots ou des bots sont encore actifs.",
    #                 'data': {
    #                     'active_bots': bot_ids
    #                 }
    #             }, status=status.HTTP_409_CONFLICT)

    #         user_archive_collection = mongo_service.get_collection("user_archive")
            
    #         user =  user_service.get_user_by_id(user_id)
    #         user_archive = user

    #         user_archive["motif"] = motif
    #         user_archive["deleted_at"] = datetime.utcnow()
    #         user_archive["deleted_by"] = user_uid
    #         user_archive["user_archive_id"] = get_next_sequence_value("user_archive_id")
            
    #         user_archive_collection.insert_one(user_archive)
            
    #         success = user_service.delete_user(user_id)
            
    #         if not success:
    #             return Response({
    #                 'success': False,
    #                 'message': 'Utilisateur non trouvé ou erreur lors de la suppression'
    #             }, status=status.HTTP_404_NOT_FOUND)
            
    #         return Response({
    #             'success': True,
    #             'message': 'Utilisateur supprimé avec succès'
    #         })
    #     except Exception as e:
    #         return Response({
    #             'success': False,
    #             'message': str(e),
    #             'error': str(e)
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, user_id):
        """
        Supprimer un utilisateur LDAP par son ID utilisateur.

        Args:
            request: Objet Request DRF
            user_id: ID de l'utilisateur à supprimer

        Returns:
            Response: Réponse HTTP avec statut et données appropriés
        """
        try:
            # 1. Vérification du motif
            motif = request.query_params.get("motif")
            if not motif:
                return Response(
                    {
                        'success': False,
                        'message': 'Le motif de suppression est obligatoire.',
                        'error_code': 'MISSING_MOTIF'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 2. Vérification des bots actifs
            bot_collection = mongo_service.get_collection('bot')
            active_bots = list(bot_collection.find(
                {
                    'assigned_user_id': user_id,
                    'status': {'$ne': 3}  # Ajoute cette condition pour exclure les bots avec status = 3
                },
                {'_id': 0, 'bot_id': 1}  # Ajout du nom pour plus d'informations
            ))

            if active_bots:
                bot_details = [{
                    bot['bot_id'],
                } for bot in active_bots]

                return Response({
                    'success': False,
                    'message': "Impossible de supprimer l'utilisateur car des bots sont encore actifs.",
                    'data': {
                        'active_bots': bot_details,
                        'count': len(active_bots)
                    },
                    'error_code': 'ACTIVE_BOTS_EXIST'
                }, status=status.HTTP_409_CONFLICT)

            # 3. Archivage de l'utilisateur
            user_archive_collection = mongo_service.get_collection("user_archive")
            user = user_service.get_user_by_id(user_id)

            if not user:
                return Response({
                    'success': False,
                    'message': 'Utilisateur non trouvé.',
                    'error_code': 'USER_NOT_FOUND'
                }, status=status.HTTP_404_NOT_FOUND)

            # Préparation des données d'archivage
            user_archive = {
                **user,
                'motif': motif,
                'deleted_at': datetime.utcnow(),
                'deleted_by': request.user.uid_number,
                'user_archive_id': get_next_sequence_value("user_archive_id")
            }

            # 4. Archivage et suppression
            try:
                # Archivage
                user_archive_collection.insert_one(user_archive)

                # Suppression
                success = user_service.delete_user(user_id)

                if not success:
                    # En cas d'échec de suppression, on pourrait aussi supprimer l'entrée d'archive
                    # mais c'est une décision de design à prendre
                    return Response({
                        'success': False,
                        'message': 'Échec de la suppression de l\'utilisateur.',
                        'error_code': 'DELETION_FAILED'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({
                    'success': True,
                    'message': 'Utilisateur supprimé avec succès.',
                    'data': {
                        'user_id': user_id,
                        'archive_id': user_archive['user_archive_id'],
                        'deleted_at': user_archive['deleted_at'].isoformat()
                    }
                })

            except Exception as archive_error:
                # En cas d'erreur pendant l'archivage ou la suppression
                return Response({
                    'success': False,
                    'message': f"Erreur lors de l'archivage ou de la suppression: {str(archive_error)}",
                    'error_code': 'ARCHIVE_DELETION_ERROR'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Gestion des erreurs générales
            return Response({
                'success': False,
                'message': 'Une erreur interne est survenue.',
                'error': str(e),
                'error_code': 'INTERNAL_SERVER_ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request,user_id):
        """
            modification des Utilisateurs
        """
        print(f"Donne recus=======================================\n")
        print(f"{request.data}")
        print("=======================================\n")
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

from rest_framework import viewsets, status    
class UserSimpleAuth(APIView):
    permission_classes = [AllowAny] 
    def post(self,request):
        try:
            email =  request.data.get("email")
            password =  request.data.get("password")
            if not email or not password:
                return Response({
                    'success': False,
                    'message': 'Email ou Mot de Passe vide'
                }, status=status.HTTP_400_BAD_REQUEST)
            ldap_service = LDAPService()
            print(f"=============================================\n")
            print(f"{email} + {password}")
            print(f"\n=============================================\n")
            user_info = ldap_service.authenticate_user(email,password)
            if not user_info:
                return Response({
                    'success': False,
                    'message': 'Mot de passe ou email incorrect'
                }, status=status.HTTP_200_OK)
            
            return Response({
                'success':True,
                'message': 'Authetification validée',
            }, status=status.HTTP_200_OK)      
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Erreur lors de l\'authentification de l\'utilisateur',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            