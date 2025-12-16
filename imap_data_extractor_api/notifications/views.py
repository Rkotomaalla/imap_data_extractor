from django.shortcuts import render
from rest_framework import viewsets, status
from bots.permissions import IsBot
from bots.authentication import BotJWTAuthentication
# Create your views here.
from datetime import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .services import send_notification
from django.conf import settings
from .serializer import NotificationSerializer
from imap_data_extractor_api.utils import get_next_sequence_value,serialize_mongo_doc
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from authentication.authentication import CustomJWTAuthentication
from configurations.services import mongo_service

class NotificationViewSet(viewsets.ViewSet):
    "viewSet pour les Notifications"
    authentication_classes = [BotJWTAuthentication]
    permission_classes=[IsBot]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.collection = mongo_service.get_collection('notification')
        
    def create(self,request):
        serializers=NotificationSerializer(data=request.data);
        if serializers.is_valid():
            try:
                token_payload = request.auth    
                bot_id=token_payload.get("bot_id")
                assigned_user_id=token_payload.get("assigned_user_id")
                notif_data=serializers.validated_data
                notif_data["timestamp"]=datetime.utcnow()
                notif_data["notif_id"]=get_next_sequence_value('notif_id')
                notif_data["bot_id_from"]=bot_id
                notif_data["assigned_user_id"]=assigned_user_id
                notif_data["read"]=False
                result = self.collection.insert_one(notif_data)
                created_data = self.collection.find_one({'_id':result.inserted_id})
                created_data = serialize_mongo_doc(created_data)
                
                send_notification(created_data)
                
                response_serializer = NotificationSerializer(created_data)
                
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response(
                    {'error': f'Erreur lors de la creation: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

    
    
    @action(
            detail=True,
            methods=['post'],
            authentication_classes=[CustomJWTAuthentication],
            permission_classes=[IsAuthenticated],
            url_path='read')
    def mark_as_read(self,request,pk=None):
        """
        pk = l'_id' de la notification (ex: "8f3e9d2a-...")
        """
        result = self.collection.update_one(
            {
                "notif_id": int(pk),
                "assigned_user_id": str(request.user.uid_number)   # sécurité : on vérifie que c'est bien à lui
            },
            {
                "$set": {
                    "read": True,
                    "updated_at": timezone.now()
                }
            }
        )
        print(f"===================================================\n{result}\n===============================================================")
        
        if result.modified_count == 1:
            return Response({"status": "read"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "not_found_or_not_owner"}, status=status.HTTP_404_NOT_FOUND)