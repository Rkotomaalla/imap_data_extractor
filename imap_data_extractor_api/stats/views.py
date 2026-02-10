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