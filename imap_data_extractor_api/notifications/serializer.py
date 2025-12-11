from rest_framework import serializers

from django.db import transaction
from django.conf import settings


class NotificationSerializer(serializers.Serializer):
    bot_id_from  = serializers.IntegerField(read_only=True) 
    notif_id= serializers.IntegerField(read_only=True)
    id=serializers.CharField(read_only=True)
    assigned_user_id=serializers.IntegerField(read_only = True)
    type=serializers.CharField(
        max_length=200,
        required=True,
        error_messages={
            'required': "Le type de notification est obligatoire.",
            'max_length': "Le type ne doit pas dépasser 200 caractères."
        }
    )
    title=serializers.CharField(
        max_length =1000, 
        required = True,
        error_messages={
            'required': "Le titre de notification est obligatoire.",
            'max_length': "Le type ne doit pas dépasser 1000 caractères."
        }
    )
    message=serializers.CharField(
        required = True,
        error_messages={
            'required': "Le message  de notification est obligatoire."
        }
    )
    timestamp=serializers.DateTimeField(read_only=True)
    
    read=serializers.BooleanField(
        read_only=True
    )
    
    category=serializers.CharField(
        required=True,
        error_messages={
            'required': "Le categorie  de notification est obligatoire.",
        }
    )
