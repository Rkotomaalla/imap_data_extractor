from django.shortcuts import render
from rest_framework.decorators import action
from rest_framework import viewsets, status
from rest_framework.response import Response
from datetime import datetime
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from configurations.services import mongo_service
from bots.service import bot_service
from datetime import timedelta
# Create your views here.
class StatsViewSet(viewsets.ViewSet):
    "View set pour tout les statistiques"
    permission_classes=[IsAuthenticated]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    @action(
        detail = False,
        methods = ["get"],
        url_path = r"attachments/count"
    )
    def get_att_count(self,request):
        try:
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            bot_collection = mongo_service.get_collection("attachment_email")

            # sécurisation utilisateur
            user_id = getattr(request.user, "uid_number", None)
            user_role = getattr(request.user, "ldap_role", None)

            if not user_id:
                return Response(
                    {"error": "Utilisateur non authentifié"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            match_stage = {
                "created_at" : {
                    "$gte": today_start,
                    "$lt": today_end
                }
            }
            
            if user_role == "user":
                match_stage["started_by"] = user_id 
                
            
            else:
                own = request.query_params.get("own", "false").lower() == "true"
                if own:
                    match_stage["started_by"] = user_id 
                    
            count = bot_collection.count_documents(match_stage)

            
            return Response(
                {                    
                    "label": "Piece jointes Telechargées Aujourd'hui",
                    "count": count,
                },
                status=status.HTTP_200_OK,
            )
            
        except ValueError:
            return Response(
                {"error": "id_status invalide"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
    
    @action(
        detail=False,
        methods=["get"],
        url_path=r"tasks/count"
    )
    def get_task_count(self,request):
        try:
            
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            
            bot_collection = mongo_service.get_collection("task")

            # sécurisation utilisateur
            user_id = getattr(request.user, "uid_number", None)
            user_role = getattr(request.user, "ldap_role", None)

            if not user_id:
                return Response(
                    {"error": "Utilisateur non authentifié"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            match_stage = {
                "started_at" : {
                    "$gte": today_start,
                    "$lt": today_end
                }
            }
            
            if user_role == "user":
                match_stage["started_by"] = user_id 
                
            
            else:
                own = request.query_params.get("own", "false").lower() == "true"
                if own:
                    match_stage["started_by"] = user_id 
                           
            count = bot_collection.count_documents(match_stage)

            return Response(
                {                    
                    "label": "Taches Effectués Aujourd'hui",
                    "count": count,
                },
                status=status.HTTP_200_OK,
            )
            
        except ValueError:
            return Response(
                {"error": "id_status invalide"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(
    detail=False,
    methods=["get"],
    url_path=r"bot/status/(?P<id_status>\d+)/count"
    )
    def bot_status_count_user(self, request, id_status):
        try:
            bot_collection = mongo_service.get_collection("bot")

            # sécurisation utilisateur
            user_id = getattr(request.user, "uid_number", None)
            user_role = getattr(request.user, "ldap_role", None)

            if not user_id:
                return Response(
                    {"error": "Utilisateur non authentifié"},
                    status=status.HTTP_401_UNAUTHORIZED
                )


            status_id = int(id_status)

            match_stage = {"status": status_id}
            
            if user_role == "user":
                match_stage["assigned_user_id"] = user_id 
            
            else:
                own = request.query_params.get("own", "false").lower() == "true"
                if own:
                    match_stage["assigned_user_id"] = user_id 
                      

            count = bot_collection.count_documents(match_stage)

            return Response(
                {
                    "status": status_id,
                    "label": bot_service.STATUS_LABELS.get(status_id),
                    "count": count,
                },
                status=status.HTTP_200_OK,
            )

        except ValueError:
            return Response(
                {"error": "id_status invalide"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        
        
    @action(
        detail = False,
        methods=["get"],
        url_path = "bot/status/count"
    )
    def bot_status_count(self,request):
        try:
            bot_collection =  mongo_service.get_collection("bot")
            
            
            user_role = getattr(request.user, 'ldap_role', None)
            user_id = getattr(request.user,'uid_number',None)

            match_stage = {}
            
            if user_role == "user":
                match_stage["assigned_user_id"] = user_id 
            
            else:
                own = request.query_params.get("own", "false").lower() == "true"
                if own:
                    match_stage["assigned_user_id"] = user_id     
                    
            pipeline = [
                {
                    "$match" : match_stage    
                },
                {
                    "$group" : 
                        {
                            "_id" : "$status",
                            "count" : {"$sum" : 1}
                        }
                }
            ]
            results =  bot_collection.aggregate(pipeline)
            formatted_results = [
                {
                    "status": r["_id"],
                    "label" : bot_service.STATUS_LABELS.get(r["_id"]),
                    "count": r["count"]
                }
                for r in results
            ]
            return Response(
                formatted_results , status=status.HTTP_200_OK
            )
            
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
    
    @action(
        detail = False,
        methods=["get"],
        url_path = "mail/count"
    )
    def extracted_mail_count(self,request):
        try:
            """  """
            filtered_emails_collection = mongo_service.get_collection("filtered_emails")
            datemax_str = request.query_params.get("datemax")
            datemin_str = request.query_params.get("datemin")
            
            if datemin_str:
                datemin = parse_datetime(datemin_str)
                if datemin is None:
                    raise ValueError("Format de date invalide pour datemin")
                if timezone.is_naive(datemin):
                    datemin = timezone.make_aware(datemin)
            else:
                datemin = timezone.make_aware(datetime(1970, 1, 1))
            
            if datemax_str:
                datemax = parse_datetime(datemax_str)
                if datemax is None:
                    raise ValueError("Format de date invalide pour datemax")
                if timezone.is_naive(datemax):
                    datemax = timezone.make_aware(datemax)
            else:
                datemax = timezone.now()  
                
            id_bot = request.query_params.get("id_bot")
            match_stage = {
                "received_at": {"$gte": datemin, "$lt": datemax}
            }
            
            user_role = getattr(request.user, 'ldap_role', None)
            user_id = getattr(request.user,'uid_number',None)
            if id_bot:
                match_stage["bot_id"] = id_bot  # ou le champ exact dans Mongo
            
            if  user_role == 'user':
                match_stage["user_id"] = user_id
            else:
                own_mail = bool(request.query_params.get("own_mail"))
                if own_mail:
                    match_stage["user_id"] = user_id

            pipeline = [ {
                                            "$match": match_stage
                                    },
                                    {
                                        "$group": {
                                            "_id": {
                                                "year": {"$year": "$received_at"},
                                                "month": {"$month": "$received_at"},
                                            },
                                            "count": {"$sum": 1}
                                        }
                                    },
                                    {
                                        "$sort": {
                                            "_id.year": 1,
                                            "_id.month": 1
                                        }
                                    }
                                ]
            
            results = list(filtered_emails_collection.aggregate(pipeline))
            formatted_results = [
                {
                    "year": r["_id"]["year"],
                    "month": r["_id"]["month"],
                    "count": r["count"]
                }
                for r in results
            ]
            return Response({"results": formatted_results}, status=status.HTTP_200_OK)
        
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    @action(
        detail = False,
        methods=["get"],
        url_path = "email/all"
    )
    def get_all_mail (self,request):
        try:
            user_id = request.user.uid_number
            all = request.query_params.get("all")
            role = request.user.ldap_role
            collection = mongo_service.get_collection("filtered_emails")
            if all == True and role == "admin":
                count_unique = len(collection.distinct("gmail_message_id"))
            else:
                count_unique = len(collection.distinct("gmail_message_id", {"user_id": user_id}))

            return Response({"count": count_unique}, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    
    @action(
        detail = False,
        methods=["get"],
        url_path = "raw_email/all"
    )
    def get_all_raw_emails (self,request):
        try:
            user_id = request.user.uid_number
            all = request.query_params.get("all")
            role = request.user.ldap_role
            collection = mongo_service.get_collection("raw_emails")
            if all == True and role == "admin":
                count_unique = len(collection.distinct("gmail_message_id"))
            else:
                count_unique = len(collection.distinct("gmail_message_id", {"user_id": user_id}))

            return Response({"count": count_unique}, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    @action(
        detail=False,
        methods=["get"],
        url_path="task/active"
    )
    def get_active_task_count(self, request):
        try:
            user_id = request.user.uid_number
            role = request.user.ldap_role

            # convertir query param en bool
            all_param = request.query_params.get("all", "false").lower() in ["true", "1", "yes"]

            collection = mongo_service.get_collection("task")

            if all_param and role == "admin":
                query = {"date_ended": None}
            else:
                query = {"started_by": user_id, "date_ended": None}

            count_unique = collection.count_documents(query)

            return Response({"count": count_unique}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
    @action(
        detail = False,
        methods = ["get"],
        url_path = "bot/ranking"
    )
    def get_bot_ranking(self, request):
        try:
            user_id = request.user.uid_number  # Exemple : 11004
            role = request.user.ldap_role
            all_param = request.query_params.get("all", "false").lower() in ["true", "1", "yes"]

            # Récupère les collections MongoDB
            collection_emails = mongo_service.get_collection("filtered_emails")
            collection_bots = mongo_service.get_collection("bot")

            # Filtre pour les mails : user_id = 11004 (sauf si admin et all_param=True)
            match_emails = {"user_id": user_id}
            if all_param and role == "admin":
                match_emails = {}  # Pas de filtre si admin et all_param=True

            # Filtre pour les bots : assigned_user_id = user_id (sauf si admin et all_param=True)
            match_bots = {"assigned_user_id": user_id}
            if all_param and role == "admin":
                match_bots = {}  # Pas de filtre si admin et all_param=True

            # --- Étape 1 : Récupère tous les bots du user_id ---
            all_bots = list(collection_bots.find(match_bots, {"bot_id": 1, "name": 1, "_id": 0}))

            # --- Étape 2 : Récupère le nombre de mails par bot_id ---
            emails_by_bot = list(collection_emails.aggregate([
                {"$match": match_emails},
                {"$group": {"_id": "$bot_id", "count": {"$sum": 1}}}
            ]))

            # --- Étape 3 : Fusionne les résultats ---
            bot_dict = {bot["bot_id"]: bot for bot in all_bots}
            for email in emails_by_bot:
                bot_id = email["_id"]
                if bot_id in bot_dict:
                    bot_dict[bot_id]["count"] = email["count"]

            # --- Étape 4 : Ajoute count=0 pour les bots sans mails ---
            for bot in bot_dict.values():
                bot.setdefault("count", 0)

            # --- Étape 5 : Convertit en liste et trie ---
            result = sorted(bot_dict.values(), key=lambda x: x["count"], reverse=True)

            # Retourne le résultat
            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
            
    @action(
        detail = False,
        methods = ["get"],
        url_path = "task"
    )
    def get_all_task(self,request):
        try:
            user_id = request.user.uid_number  # Exemple : 11004
            role = request.user.ldap_role 
            
            # convertir query param en bool
            all_param = request.query_params.get("all", "false").lower() in ["true", "1", "yes"]
            if all_param and role == "admin":
                query = {}
            else:
                query = {"started_by": user_id}
            collection = mongo_service.get_collection("task")
            count_unique = collection.count_documents(query)

            return Response(count_unique, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        