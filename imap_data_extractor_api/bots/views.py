from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin
from rest_framework.response import Response
from rest_framework import status
from mail.serializer import EmailFilterSerializer , EmailListSerializer

from .serializer import BotSerializer
import logging
from django.db import transaction
from imap_data_extractor_api.utils import get_next_sequence_value
from datetime import datetime, timedelta
# les nouveaux import
from rest_framework import viewsets, status
from django.conf import settings
from datetime import datetime
from imap_data_extractor_api.utils import serialize_mongo_doc, parse_object_id

from mail.serializer import MailSerializer
from .service import bot_service
from rest_framework.decorators import action

from rest_framework.exceptions import APIException
# generate_bot_token, is_bot_owner, stop_bot,delete_bot
from configurations.services import  mongo_service
logger = logging.getLogger(__name__)
# # Create your views here.
# class BotsView(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request):
#         return Response({'success': True, 'message': 'Tongasoa ee'}, status=201)
#     def post(self,request):
#         """Creer un nouvel Bot"""
#         data = request.data.copy()  # copier les données reçues
#         data['assigned_user'] = request.user.username
#         data['assigned_user_id'] = request.user.id 
#         print(f"\n================================================={data}\n")
#         serializer = BotSerializer(data=data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()  # crée Bot + BotFilter + BotRules en une seule fois
#         return Response({'success': True, 'message': 'Bot créé avec succès'}, status=201)
    
    
    
    
class BotViewSet(viewsets.ViewSet):
    """ViewSet CRUD pour les Bots avec PyMongo""" 
    permission_classes = [IsAuthenticated]
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.collection = mongo_service.get_collection('bot')   
    
#CREATION D UN BOT======================================================================================================================================================    
    def create(self,request):
        serializer=BotSerializer(data=request.data)
        # Fonction ajout les validation des datas actions
        
        if serializer.is_valid():
            try:
                bot_data = serializer.validated_data
                bot_data['created_date'] = datetime.utcnow()
                bot_data['killed_date'] =  None
                bot_data['assigned_user_id'] = request.user.uid_number
                bot_data['bot_id'] = get_next_sequence_value('bot_id') 
                
                #  insertion dans mongoDb
                result=self.collection.insert_one(bot_data)   
                
                # # Récupération du document créé avec le serializer pour obtenir assigned_user
                created_bot = self.collection.find_one({'_id': result.inserted_id})
                created_bot = serialize_mongo_doc(created_bot)
                response_serializer = BotSerializer(created_bot)
                
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
                # return Response(bot_data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response(
                    {'error': f'Erreur lors de la création: {str(e)}'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#LISTE DE TOUT LES BOTS========================================================================================================
    def list(self, request):
        """GET /bots/ - Liste tous les bots de l'utilisateur connecté"""
        try:
            # Récupération avec pagination
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size

            # Filtres de base : uniquement les bots de l'utilisateu
            filters = {'assigned_user_id': request.user.uid_number}
            
            # Filtres optionnels
            if 'status' in request.query_params:
                filters['status'] = int(request.query_params['status'])
            if 'name' in request.query_params:
                filters['name'] = {'$regex': request.query_params['name'], '$options': 'i'}
            
            if 'date' in request.query_params:
                # Récupérer la date depuis la query string
                date_str = request.query_params['date']  # ex: "2026-02-11"

                # Convertir en objet datetime
                date_obj = datetime.strptime(date_str, "%Y-%m-%d")

                # Filtre MongoDB pour matcher exactement ce jour
                # Ici on utilise $gte / $lt pour couvrir toute la journée
                filters['created_date'] = {
                    "$gte": date_obj,
                    "$lt": date_obj.replace(hour=23, minute=59, second=59, microsecond=999999)
                }
                
            # Tri
            sort_order = 1 if request.query_params.get('dateSort', '0') == '0' else -1

            # Requête MongoDB
            total = self.collection.count_documents(filters)
            bots = list(self.collection.find(filters).skip(skip).limit(page_size).sort("created_date", sort_order))
            
            # Sérialisation avec contexte utilisateur
            bots_data = [serialize_mongo_doc(bot) for bot in bots]
            serializer = BotSerializer(bots_data, many=True)
            
            return Response({
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': serializer.data
            })
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la récupération: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
           
           
           
#RECUPERATION D UN BOT PAR SON ID ================================================================================================================ 
    def retrieve(self, request, pk=None):
        """GET /api/bots/{id}/ - Récupère un bot spécifique (vérifie ownership)"""
        try:
            # object_id = parse_object_id(pk)
            uid_number = request.user.uid_number
            bot = self.collection.find_one({
                'bot_id': int(pk),
                'assigned_user_id': uid_number  # ← Sécurité : vérifie l'ownership
            })
            print(bot)
            if not bot:
                return Response(
                    {'error': 'Bot non trouvé ou accès refusé'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            bot = serialize_mongo_doc(bot)
            serializer = BotSerializer(bot)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {'error': f'Erreur: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
#MODIFICATION D'UN BOT====================================================================================================================
    def partial_update(self,request,pk=None):
        """PATCH  /bots/{id} => modiffier un Bot"""
        try:
            bot =  self.collection.find_one({
                'bot_id': int(pk),
            })
            if not bot:
                return Response(
                    {'error': 'Bot non trouvé'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            # Eto ny ownerShip
            if str(bot.get('assigned_user_id')) != str(request.user.uid_number):
                return Response(
                {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                status=status.HTTP_403_FORBIDDEN
                )
                
            # Serializer avec partial=True pour permettre update partiel
            serializer = BotSerializer(bot, data=request.data, partial=True)
            if serializer.is_valid():
                validated_data = serializer.validated_data
                # Mettre à jour uniquement les champs envoyés
                updated_bot = {**bot, **validated_data}

                # Sauvegarde dans MongoDB
                self.collection.update_one(
                    {'_id': bot['_id']},
                    {'$set': updated_bot}
                )

                # Recharger le document pour la réponse
                updated_bot = self.collection.find_one({'_id': bot['_id']})
                updated_bot = serialize_mongo_doc(updated_bot)

                response_serializer = BotSerializer(updated_bot)
                return Response(response_serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                 {'error': f'Erreur: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
#Activation du bot================================================================================================================================================            
    @action(detail=True, methods=['post'], url_path="activate",permission_classes=[IsAuthenticated])
    def activate_bot(self, request , pk=None):
        """Activer un bot POST /bots/[id]/activate"""
        try:
            bot_id = int(pk)
            user_id = int(request.user.uid_number)
        except (TypeError, ValueError):
            return Response(
                {'detail': 'Identifiants invalides.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        user_role =  request.user.ldap_role
        print("Tonga eto am Activate Bot==============================")

        try:
            if not bot_service.is_bot_owner(bot_id,user_id,user_role):
                 return Response(
                    {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            bot = bot_service.get_by_id(bot_id)
            if not bot:
                return Response(
                    {'detail': 'Bot introuvable.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            if bot.get("status") in (0, 1):
                return Response(
                    {'error' : 'Bot est en cours d\'execution '},
                    status=status.HTTP_409_CONFLICT
                )
            created_task = bot_service.activate_bot(bot_id)
            return Response(
                {
                    'message' : f'Le bot avec l\'identifiant {bot_id} est activé',
                    'status' : "success",
                    'created_task' : created_task    
                },
                status = status.HTTP_200_OK
            )
        except APIException as e:
            # Laisse DRF gérer le status (409, 400, etc.)
            raise e

        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error' : f'erreur lors de l\'activaion du bot : {str(e)}'},
                status =  status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
        
#Restart bot======================================================s==========================================================================================            
    @action(detail  = True,methods=["post"],url_path = "start" , permission_classes=[IsAuthenticated])
    def start_bot(self,request,pk=None):
        """POST bots/{id}/pause"""
        try:
            bot_id = int(pk)
            user_id =  int(request.user.uid_number)
        except (TypeError, ValueError):
            return Response(
                 {'detail' : 'identifiants invalides.'},
                 status = status.HTTP_400_BAD_REQUEST
            ) 
        try:
            user_role =  request.user.ldap_role
            if not bot_service.is_bot_owner(bot_id,user_id,user_role):
                return Response(
                    {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            bot = bot_service.get_by_id(bot_id)
            if not bot:
                return Response(
                    {'detail': 'Bot introuvable.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            if bot and bot.get("status") == 1:
                return Response(
                    {'error': 'Le bot deja en etat de marche.'},
                    status=status.HTTP_409_CONFLICT
                )
            bot_service.start_bot(bot_id)
            return Response(
                {
                    "status": "succes",
                    "message": f"bot {bot_id} mise en marche avec succes "
                }
            )
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except RuntimeError as e:
            return Response({"error": str(e)}, status=status.HTTP_409)
        except Exception as e:
            return Response(
                {'error' : f'erreur lors dela mis en pause du bot : {str(e)}'},
                status =  status.HTTP_500_INTERNAL_SERVER_ERROR
            )
#Pause du bot======================================================s==========================================================================================            
    @action(detail  = True,methods=["post"],url_path = "pause" , permission_classes=[IsAuthenticated])
    def pause_bot(self,request,pk=None):
        """POST bots/{id}/pause"""
        try:
            bot_id = int(pk)
            user_id =  int(request.user.uid_number)
        except (TypeError, ValueError):
            return Response(
                 {'detail' : 'identifiants invalides.'},
                 status = status.HTTP_400_BAD_REQUEST
            ) 
        try:
            user_role =  request.user.ldap_role
            if not bot_service.is_bot_owner(bot_id,user_id,user_role):
                return Response(
                    {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            bot = bot_service.get_by_id(bot_id)
            if not bot:
                return Response(
                    {'detail': 'Bot introuvable.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            if bot and bot.get("status") == 0:
                return Response(
                    {'error': 'Le bot deja en etat de pause.'},
                    status=status.HTTP_409_CONFLICT
                )
            bot_service.pause_bot(bot_id)
            return Response(
                {
                    "status": "succes",
                    "message": f"bot {bot_id} mise en pause avec succes "
                }
            )
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except RuntimeError as e:
            return Response({"error": str(e)}, status=status.HTTP_409_CONFLICT)
        except Exception as e:
            return Response(
                {'error' : f'erreur lors dela mis en pause du bot : {str(e)}'},
                status =  status.HTTP_500_INTERNAL_SERVER_ERROR
            )
# Arret Du bot  ================================================================================================
    @action(detail=True, methods = ['post'] , url_path="stop", permission_classes=[IsAuthenticated])
    def stop_bot(self,request,pk=None):
        """POST /bots/{id}/stop"""
        try:
            bot_id = int(pk)
            user_id = int(request.user.uid_number)
        except (TypeError, ValueError):
            return Response(
                {'detail': 'Identifiants invalides.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        user_role =  request.user.ldap_role
        try:
            if not bot_service.is_bot_owner(bot_id,user_id,user_role):
                return Response(
                    {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            bot = bot_service.get_by_id(bot_id)
            if not bot:
                return Response(
                    {'detail': 'Bot introuvable.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            if bot and bot.get("status") == 2:
                return Response(
                    {'error': 'Le bot deja en etat d\'arret.'},
                    status=status.HTTP_409_CONFLICT
                )
            bot_service.stop_bot(bot_id)
            return Response(
                {
                    'message': f'Le bot avec l\'identifiant {bot_id} a été arrêté avec succès.',
                    'status' : 'success'
                },
                status=status.HTTP_200_OK
            )
            
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error' : f'Erreur lors de l\'arrêt du bot: {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
#SUPPRESSION DU BOT ======================================================================================================================================
    @action(detail=True, methods=['delete'] ,url_path = "delete_bot",permission_classes=[IsAuthenticated])  
    def delete_bot(self, request, pk=None): 
        """DELETE /bots/{id}/ - Supprimer un bot (vérifie ownership)"""
        try:
            bot_id = int(pk)
            user_id = int(request.user.uid_number)
        except (TypeError, ValueError):
            return Response(
                {'detail': 'Identifiants invalides.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        user_role =  request.user.ldap_role
        try:
            if not bot_service.is_bot_owner(bot_id,user_id,user_role):
                return Response(
                    {'error': 'Accès refusé. Ce bot ne vous appartient pas.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            bot = bot_service.get_by_id(bot_id)
            if bot and bot.get("status") == 1 : 
                bot_service.stop_bot(bot_id)
            # changer le status du bot par effacer
            bot_service.delete_bot(bot_id,user_id)
            return Response(
                {
                    'message': f'Le bot avec l\'identifiant {bot_id} a été supprimé avec succès.',
                    'status' : 'success'
                },
                status=status.HTTP_200_OK
            )
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e : 
            return Response(
                {'error' : f'Erreur lors de la suppression: {str(e)}'},
                status = status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            

#GENERATION D'UN TOKEN POUR UN BOT================================================================================================================
    @action(detail=True, methods=['get'], url_path="tokens", permission_classes=[IsAuthenticated])
    def getToken(self, request, pk=None):
        """
        URLs Spécifique : GET /bots/<id>/token/
        Génère un token JWT pour le bot spécifié
        """
        try:
            # Récupérer le bot depuis MongoDB
            bot = self.collection.find_one({
                'bot_id': int(pk),
                # 'assigned_user_id': request.user.uid_number  # Décommentez si nécessaire
            })
            
            if not bot:
                logger.warning(f"Bot non trouvé : bot_id={pk}")
                return Response(
                    {'error': f'Bot avec id {pk} non trouvé'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Sérialiser le bot
            bot = serialize_mongo_doc(bot)
            serializer = BotSerializer(bot)
            bot_data = serializer.data
            
            # Générer le token
            bot_id = bot_data.get('bot_id')  # ou 'id' selon votre modèle
            assigned_user_id = bot_data.get('assigned_user_id')
            token = bot_service.generate_bot_token(bot_id, assigned_user_id)
            
            logger.info(f"✅ Token généré pour bot_id={bot_id}")
            
            return Response(
                {
                    "access": token,
                    "bot_id": bot_id,
                    "bot_name": bot_data.get('name', 'N/A'),
                    "expires_in": "30 days"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"❌ Erreur lors de la génération du token: {str(e)}")
            return Response(
                {"error": f"Erreur lors de la génération du token: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
#EMAIL PAR ID BOT================================================================================================================================================            
    @action(detail= True , methods=['get'],url_path="mail", permission_classes=[IsAuthenticated])
    def get_email_by_id_bot(self,request,pk=None):
        """/GET /bot/{id}/mail"""        
        try:
            # Récupération avec pagination
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size
            
            ESSENTIAL_FIELDS = {
                "_id": 0,
               "gmail_message_id" : 1,
                "subject" : 1,
                "from" : 1,
                "received_at" : 1,
                "date" : 1,
                "has_attachment" : 1
            }
                        
            # Date par défaut pour end_date : aujourd'hui + 10 ans
            serializer = EmailFilterSerializer(data = request.query_params)           
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            filter_data=serializer.validated_data
            filter_data = {k: v for k, v in filter_data.items() if v is not None}
            filter_data["bot_id"] = int(pk)
            
            mail_collection = mongo_service.get_collection("filtered_emails")
            

            
            total = mail_collection.count_documents(filter_data)
            mails = list(mail_collection.find(filter_data).skip(skip).limit(page_size))
            
            emails =  list(
                mail_collection
                        .find(filter_data,ESSENTIAL_FIELDS)
                        .skip(skip)
                        .limit(page_size)
            )
            #Serialization des Donnes trouves
            emails_data  = [serialize_mongo_doc(email) for email in emails]
            
            return Response({
                    'count': total,
                    'page': page,
                    'page_size': page_size,
                    'results': emails_data
                })
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la récupération: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
#Compte des bots
    @action(detail = False, methods=['get'],url_path="count" , permission_classes=[IsAdmin])
    def count_bot(self, request):
        try:
            counted_bot = bot_service.get_count()
            return Response({"data": counted_bot}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'success':False,'error': f'Erreur lors de la récupération des comptes des bots: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(detail = False, methods=['get'],url_path="count_own" , permission_classes=[IsAuthenticated])
    def count_own_bot(self, request):
        try:
            try:
                id_user = int(request.query_params.get('user_id') or request.user.uid_number)
            except (ValueError, TypeError):
                return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)
            
            counted_bot = bot_service.get_own_bot_count(id_user)
            return Response({"data": counted_bot}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'success':False,'error': f'Erreur lors de la récupération des comptes des bots: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
#Foonction poiur prendre le nombre total du bot d un utilisateur   
    @action(detail = False, methods=['get'],url_path="total_count" , permission_classes=[IsAuthenticated])   
    def count_user_bot(self,request):
        try:
            try:
                id_user = int(request.query_params.get('user_id') or request.user.uid_number)
            except (ValueError, TypeError):
                return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)
            query_filter = {
                "assigned_user_id" : id_user
            }
            count = self.collection.count_documents(query_filter)
            return Response({
                'success' : True,
                'count': count},
                status = status.HTTP_200_OK
            )   
        except Exception as e:
            return Response(
                {'success':False,'error': f'Erreur lors de la récupération des comptes des bots: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    
#Statistique des details du bot        
    @action(detail=True, methods=['get'], url_path="stats/filtered_mail", permission_classes=[IsAuthenticated])
    def count_filtered_mail(self, request, pk=None):
        try:
            id_bot = int(pk)
            if not id_bot:
                return Response(
                    {'error': 'L\'identifiant du bot est invalide ou manquant.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            all_count = request.query_params.get('all_count', '1')
            query = {'bot_id': id_bot}

            filtered_collection = mongo_service.get_collection('filtered_emails')

            if not all_count or all_count == '0':
                # La date doit être entre aujourd'hui et le mois dernier à compter d'aujourd'hui
                now = datetime.utcnow()
                one_month_ago = now - timedelta(days=30)
                query['date'] = {
                    '$gte': one_month_ago,
                    '$lte': now
                }
            total = filtered_collection.count_documents(query)
            return Response(
                {'count': total},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {'success':False,'error': f'Erreur lors de la récupération du nombre de mails filtrés: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
         
         