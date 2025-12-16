from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializer import BotSerializer
import logging
from django.db import transaction
from imap_data_extractor_api.utils import get_next_sequence_value

# les nouveaux import
from rest_framework import viewsets, status
from django.conf import settings
from datetime import datetime
from imap_data_extractor_api.utils import serialize_mongo_doc, parse_object_id


from .service import generate_bot_token
from rest_framework.decorators import action


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
        
    def create(self,request):
        serializer=BotSerializer(data=request.data)
        
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

    def list(self, request):
        """GET /api/bots/ - Liste tous les bots de l'utilisateur connecté"""
        try:
            # Récupération avec pagination
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            skip = (page - 1) * page_size

            # Filtres de base : uniquement les bots de l'utilisateu
            filters = {'assigned_user_id': request.user.uid_number}
            
            # Filtres optionnels
            if 'status' in request.query_params:
                filters['status'] = int(request.query_params['status'])
            if 'name' in request.query_params:
                filters['name'] = {'$regex': request.query_params['name'], '$options': 'i'}

            # Requête MongoDB
            total = self.collection.count_documents(filters)
            bots = list(self.collection.find(filters).skip(skip).limit(page_size))
            
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
            
    def retrieve(self, request, pk=None):
        """GET /api/bots/{id}/ - Récupère un bot spécifique (vérifie ownership)"""
        try:
            # object_id = parse_object_id(pk)
            bot = self.collection.find_one({
                'bot_id': int(pk),
                'assigned_user_id': request.user.uid_number  # ← Sécurité : vérifie l'ownership
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
            
            

    @action(detail=True, methods=['get'], url_path="token", permission_classes=[IsAuthenticated])
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
            token = generate_bot_token(bot_id,assigned_user_id)
            
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