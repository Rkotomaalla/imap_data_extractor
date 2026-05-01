from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from configurations.services import mongo_service


class NotificationViewSet(viewsets.ViewSet): 
    def __init__(self, **kwargs) : 
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection("mail_notification")
        
        
    @action(
    detail=False,
    methods=['get'],
    url_path="last",
    permission_classes=[IsAuthenticated]
    )
    def last_notification(self, request):
        try:
            user_id = request.user.uid_number
            bot_id = request.query_params.get("bot_id", None)

            # ✅ Filtre de base par user
            query = {"user_id": user_id}

            # ✅ Filtre optionnel par bot
            if bot_id is not None:
                query["bot_id"] = int(bot_id)

            # ✅ Récupère les 5 dernières notifications triées par date décroissante
            notifications = list(
                self.collection.find(query)
                .sort("created_at", -1)
                .limit(5)
            )

            # ✅ Sérialise les données pour le front
            result = [
                {
                    "user_id": notif.get("user_id"),
                    "bot_id": str(notif.get("bot_id", "")),
                    "mail_id": notif.get("mail_id", ""),
                    "mail_subject": notif.get("mail_subject", ""),
                    "mail_from": notif.get("mail_from", ""),
                    "name": notif.get("name", ""),
                    "message": notif.get("message", ""),
                    "is_read": notif.get("is_read", False),
                    "created_at": notif.get("created_at", ""),
                }
                for notif in notifications
            ]

            return Response(
                {"success": True, "data": result},
                status=status.HTTP_200_OK
            )

        except ValueError as e:
            return Response(
                {"success": False, "error": f"Paramètre invalide : {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"success": False, "error": f"Erreur lors de la récupération des dernières notifications: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
                
        