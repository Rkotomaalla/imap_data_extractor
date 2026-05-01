from django.shortcuts import render
import logging
from rest_framework import viewsets, status
from django.conf import settings
from .serializer import MailSerializer
from .services import mail_service
from rest_framework.response import Response
# from email.utils import parsedate_to_datetime
from datetime import datetime,timezone,timedelta
from imap_data_extractor_api.utils  import get_next_sequence_value, serialize_mongo_doc
from bots.permissions import IsBot
from rest_framework.permissions import IsAuthenticated, AllowAny
from bots.authentication import BotJWTAuthentication
from authentication.authentication import CustomJWTAuthentication
from configurations.services import mongo_service
from authentication.permissions import IsAdmin
from rest_framework.decorators import action
from .serializer import EmailFilterSerializer , EmailListSerializer
import os
import mimetypes

from django.http import FileResponse, Http404
# Create your views here.
logger=logging.getLogger(__name__)

class MailViewSet(viewsets.ViewSet):
    """ViewSet Crud des email avec pymongo"""
    # authentication_classes = [BotJWTAuthentication]
    # permission_classes = [IsBot]
    # Creation des permission des Bots
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection('filtered_emails')
        self.raw_collection = mongo_service.get_collection ('raw_emails') 
        self.filtered_collection = mongo_service.get_collection ('filtered_emails') 
    
    def get_permissions(self):
        """Permissions différentes selon l'action"""
        if self.request.method == 'GET':
            return [IsAdmin()]
        elif self.request.method == 'POST':
            return [IsBot()]
        return [IsAuthenticated()]
    
    def get_authenticators(self):
        """Authentication différente selon l'action"""
        if self.request.method == 'GET':
            return [CustomJWTAuthentication()]
        elif self.request.method == 'POST':
            return [BotJWTAuthentication()]
        return [CustomJWTAuthentication()]
    
    def list(self, request):
        """GET /page"""
        try:
            page = max(1, int(request.query_params.get('page', 1)))
            page_size = max(1, min(100, int(request.query_params.get('page_size', 10))))
            skip = (page - 1) * page_size

            serializer = EmailFilterSerializer(data=request.query_params)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            filter_data = serializer.validated_data
            filter_data = {k: v for k, v in filter_data.items() if v is not None}

            # Filtre user_id
            user_id = request.query_params.get("user_id")
            if user_id is not None:
                try:
                    print(f'{user_id}==========================ffffffffffffffffffffffffffffffffffffffffffffffffff')
                    filter_data["user_id"] = int(user_id)
                except (ValueError, TypeError):
                    return Response({"error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            bot_id = request.query_params.get("bot_id")
            if bot_id is not None:
                try:
                    filter_data["bot_id"] = int(bot_id)
                except (ValueError, TypeError):
                    return Response({"error": "bot_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            pipeline = [
                {"$match": filter_data},
                {"$group": {
                    "_id":              "$gmail_message_id",
                    "gmail_message_id": {"$first": "$gmail_message_id"},
                    "from":             {"$first": "$from"},
                    "subject":          {"$first": "$subject"},
                    "received_at":      {"$max":   "$received_at"},
                }},
                {"$sort": {"received_at": -1}},
                {"$facet": {
                    "total": [{"$count": "count"}],
                    "data":  [{"$skip": skip}, {"$limit": page_size}]
                }}
            ]

            result = list(self.collection.aggregate(pipeline))
            total  = result[0]["total"][0]["count"] if result[0]["total"] else 0
            emails = result[0]["data"]

            import re
            parsed = []         
            for mail in emails:
                raw_from = mail.get("from", "")
                match = re.match(r'^(.*?)\s*<(.+?)>$', raw_from.strip())
                if match:
                    sender_name  = match.group(1).strip().strip('"')
                    sender_email = match.group(2).strip()
                else:
                    sender_name  = ""
                    sender_email = raw_from.strip()

                parsed.append({
                    "gmail_message_id": mail.get("gmail_message_id"),
                    "sender_name":      sender_name,
                    "sender_email":     sender_email,
                    "subject":          mail.get("subject", "(Sans objet)"),
                    "received_at":      mail.get("received_at").isoformat() if mail.get("received_at") else None,
                    "bot_ids": mail_service.get_email_bots(mail.get("gmail_message_id"))
                })

            return Response({
                'count':     total,
                'page':      page,
                'page_size': page_size,
                'results':   parsed
            })

        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la recuperation des email: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    def retrieve(self, request, pk=None):
        """
        GET /mail/{id}/
        Récupère un email par son gmail_message_id
        """
        try:
            if not pk:
                return Response(
                    {"detail": "L'identifiant de l'email est requis."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            data = mail_service.get_mail_id(pk)
            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la récupération de l'email: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        


    @action(
        detail=False,
        methods=['get'],
        url_path="raw",
        permission_classes=[IsAuthenticated]
    )
    def get_raw_email(self, request):
        try:
            pk = request.query_params.get("user_id")
            if not pk:
                id = request.user.uid_number
            else:
                id = int(pk)

            date_min = request.query_params.get("date_min")
            date_max = request.query_params.get("date_max")
            count_param = request.query_params.get("count")

            query = {"user_id": id}

            # --- Filtrage par date ---
            if date_min or date_max:
                dt_min = datetime.strptime(date_min, "%Y-%m-%d").replace(tzinfo=timezone.utc) if date_min else None
                dt_max = datetime.strptime(date_max, "%Y-%m-%d").replace(tzinfo=timezone.utc) if date_max else None
                # ✅ fin de journée : 2026-03-28 23:59:59 UTC
                dt_max = dt_max + timedelta(hours=23, minutes=59, seconds=59)
                pipeline = [
                    {"$match": {"user_id": id}},
                    {"$addFields": {"parsed_date": {"$toDate": "$date"}}},
                    {"$match": {
                        "parsed_date": {
                            **({"$gte": dt_min} if dt_min else {}),
                            **({"$lte": dt_max} if dt_max else {}),
                        }
                    }},
                    {"$project": {"parsed_date": 0, "_id": 0}}
                ]

                if int(count_param) == 1:
                    total = len(list(self.raw_collection.aggregate(pipeline)))
                    return Response({
                        "success": True,
                        "count": total
                    }, status=status.HTTP_200_OK)
                else:
                    emails = list(self.raw_collection.aggregate(pipeline))
                    return Response({
                        "success": True,
                        "count": len(emails),
                        "results": emails
                    }, status=status.HTTP_200_OK)

            # --- Sans filtrage par date ---
            total = self.raw_collection.count_documents(query)

            if int(count_param) == 1:
                return Response({
                    "success": True,
                    "count": total
                }, status=status.HTTP_200_OK)
            else:
                emails = list(self.raw_collection.find(query, {"_id": 0}))
                return Response({
                    "success": True,
                    "count": total,
                    "results": emails
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la récupération de la liste des emails: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
            
    
    @action(
        detail=True,
        methods=['get'],
        url_path="filtered",
        permission_classes=[IsAuthenticated]
    )
    def get_filtered_mail(self,request,pk=None):
        try:
            id = int(pk);
            if not id:
                return Response(
                    {"succes" : False,
                    "error" : "erreur lors de la recuperation des mails traité"},
                    status = status.HTTP_400_BAD_REQUEST
                )
            query = {"bot_id": id}
            total = self.filtered_collection.count_documents(query)
            
            return Response({
                    "success": True,
                    "count": total
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"error": f"Erreur lors de la récupération d est mail extraits: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # fonction prendre le nombre de mail extrait pour un utilisateur
    @action(
        detail=False,
        methods=['get'],
        url_path="extracted",
        permission_classes=[IsAuthenticated]
    )
    def get_extracted_mail(self,request):
        try:
            try:
                id_user = int(request.query_params.get('user_id') or request.user.uid_number)
            except (ValueError, TypeError):
                return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)
            query_filter = {"user_id" : id_user}
            total = self.filtered_collection.count_documents(query_filter)
            
            return Response({
                    "success": True,
                    "count": total
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"success":False,"error": f"Erreur lors de la récupération d est mail extraits: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
        
        
    @action(
    detail=False,
    methods=['get'],
    url_path="group_extracted",
    permission_classes=[IsAuthenticated]
    )
    def get_extracted_mail_by_group(self, request):
        try:
            try:
                id_user = int(request.query_params.get('user_id') or request.user.uid_number)
            except (ValueError, TypeError):
                return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            pipeline = [
                # 1. Filtrer par utilisateur
                {
                    "$match": {"user_id": id_user}
                },
                # 2. Grouper tous les docs ensemble et collecter les gmail_message_id uniques
                {
                    "$group": {
                        "_id": None,
                        "unique_messages": {"$addToSet": "$gmail_message_id"}
                    }
                },
                # 3. Compter le nombre d'éléments dans le set
                {
                    "$project": {
                        "_id": 0,
                        "count": {"$size": "$unique_messages"}
                    }
                }
            ]

            result = list(self.filtered_collection.aggregate(pipeline))

            # Si aucun document, result est vide
            total = result[0]["count"] if result else 0

            return Response({
                "success": True,
                "count": total
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur lors de la récupération des mails extraits : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    @action(
        detail=False,
        methods=['get'],
        url_path="weekly-stats",
        permission_classes=[IsAuthenticated]
    )
    def get_weekly_stats(self, request):
        try:
            try:
                id_user = int(request.query_params.get('user_id') or request.user.uid_number)
            except (ValueError, TypeError):
                return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            # Borne de départ : il y a 7 jours à minuit UTC
            seven_days_ago = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)

            pipeline = [
                # 1. Filtrer par user et sur les 7 derniers jours
                {
                    "$match": {
                        "user_id": id_user,
                        "received_at": {"$gte": seven_days_ago}
                    }
                },
                # 2. Grouper par jour (date tronquée à minuit)
                {
                    "$group": {
                        "_id": {
                            "$dateTrunc": {
                                "date": "$received_at",
                                "unit": "day"
                            }
                        },
                        "count": {"$sum": 1}
                    }
                },
                # 3. Trier par date croissante
                {
                    "$sort": {"_id": 1}
                },
                # 4. Formater la sortie
                {
                    "$project": {
                        "_id": 0,
                        "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$_id"}},
                        "count": 1
                    }
                }
            ]

            results = list(self.filtered_collection.aggregate(pipeline))

            # Remplir les jours sans données avec count=0
            all_days = {
                (seven_days_ago + timedelta(days=i)).strftime("%Y-%m-%d"): 0
                for i in range(7)
            }
            for entry in results:
                all_days[entry["date"]] = entry["count"]

            daily_stats = [{"date": d, "count": c} for d, c in all_days.items()]

            return Response({
                "success": True,
                "data": daily_stats
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur weekly stats : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(
        detail=False,
        methods=['get'],
        url_path="recent",
    permission_classes=[IsAuthenticated]
    )
    def get_recent_mails(self, request):
        try:
            import re

            # ── Paramètres ────────────────────────────────────────────────────────
            bot_id_param  = request.query_params.get('bot_id')
            user_id_param = request.query_params.get('user_id')

            # Validation bot_id
            bot_id = None
            if bot_id_param is not None:
                try:
                    bot_id = int(bot_id_param)
                except (ValueError, TypeError):
                    return Response({"success": False, "error": "bot_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            # Validation user_id — fallback sur l'utilisateur connecté si absent
            user_id = None
            if bot_id is None:
                try:
                    user_id = int(user_id_param) if user_id_param is not None else int(request.user.uid_number)
                except (ValueError, TypeError):
                    return Response({"success": False, "error": "user_id invalide"}, status=status.HTTP_400_BAD_REQUEST)

            # ── Filtre $match ─────────────────────────────────────────────────────
            # bot_id est prioritaire ; user_id prend le relais seulement si absent
            if bot_id is not None:
                match_filter = {"bot_id": bot_id}
            else:
                match_filter = {"user_id": user_id}

            # ── Pipeline ──────────────────────────────────────────────────────────
            pipeline = [
                {"$match": match_filter},
                {"$sort": {"received_at": -1}},
                {"$group": {
                    "_id":              "$gmail_message_id",
                    "gmail_message_id": {"$first": "$gmail_message_id"},
                    "from":             {"$first": "$from"},
                    "subject":          {"$first": "$subject"},
                    "received_at":      {"$max":   "$received_at"},
                }},
                {"$sort": {"received_at": -1}},
                {"$limit": 5},
                {"$project": {
                    "_id":              0,
                    "gmail_message_id": 1,
                    "from":             1,
                    "subject":          1,
                    "received_at":      1,
                }}
            ]

            results = list(self.filtered_collection.aggregate(pipeline))

            # ── Parser le champ "from" ─────────────────────────────────────────────
            parsed = []
            for mail in results:
                raw_from = mail.get("from", "")
                match = re.match(r'^(.*?)\s*<(.+?)>$', raw_from.strip())
                if match:
                    sender_name  = match.group(1).strip().strip('"')
                    sender_email = match.group(2).strip()
                else:
                    sender_name  = ""
                    sender_email = raw_from.strip()

                parsed.append({
                    "sender_name":       sender_name,
                    "sender_email":      sender_email,
                    "subject":           mail.get("subject", "(Sans objet)"),
                    "received_at":       mail.get("received_at").isoformat() if mail.get("received_at") else None,
                    "gmail_message_id":  mail.get("gmail_message_id"),
                })

            return Response({"success": True, "data": parsed}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur récupération mails récents : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    @action(
    detail=True,
    methods=['get'],
    url_path="bot",
    permission_classes=[IsAuthenticated]
    )
    def get_bot_email(self, request,pk=None):
        try:
            if not pk:
                return Response({"success": False, "error": "id de l'email invalide"}, status=status.HTTP_400_BAD_REQUEST)

            bot_ids = mail_service.get_email_bots(pk)

            return Response({
                "success": True,
                "data": bot_ids
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur récupération mails récents : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(
        detail=True,
        methods=["get"],
        url_path="attachment_download",
        permission_classes=[IsAuthenticated],
    )
    def download(self, request, pk=None):
        """
        Télécharge une pièce jointe par son attachment_id.
        GET /api/attachments/{attachment_id}/download/
        """
        try:
            attachment_id = pk
            if not attachment_id:
                return Response(
                    {"success": False, "error": "attachment_id est obligatoire"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Récupération depuis MongoDB
            attachment_collection = mongo_service.get_collection("attachment_email")
            attachment = attachment_collection.find_one(
                {"attachment_id": attachment_id},
                {"_id": 0, "storage_path": 1, "filename": 1, "mime_type": 1}
            )
            if not attachment:
                return Response(
                    {"success": False, "error": "Pièce jointe introuvable"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            storage_path = attachment.get("storage_path", "").replace("\\", "/")
            filename = attachment.get("filename", "fichier")
            mime_type = attachment.get("mime_type") or mimetypes.guess_type(filename)[0] or "application/octet-stream"

            # Vérification que le fichier existe bien sur le disque
            if not storage_path or not os.path.exists(storage_path):
                return Response(
                    {"success": False, "error": f"Fichier introuvable sur le serveur : {storage_path}"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Ouverture et retour du fichier en streaming pour éviter les problèmes de mémoire
            try:
                file = open(storage_path, "rb")
            except IOError as e:
                return Response(
                    {"success": False, "error": f"Impossible d'ouvrir le fichier : {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            response = FileResponse(
                file,
                content_type=mime_type,
                as_attachment=True,
                filename=filename,
            )
            return response

        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur lors du téléchargement : {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )