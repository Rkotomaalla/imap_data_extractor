from rest_framework import serializers
# from .models import Bots
from django.db import transaction
from bot_filter.serializer import FilterSerializer
from django.conf import settings




class BotSerializer(serializers.Serializer):
    bot_id = serializers.IntegerField(read_only=True)
    id = serializers.CharField(read_only = True)
    name = serializers.CharField(max_length = 200 , required = True)    
    status = serializers.IntegerField(min_value=0, max_value =  2 , default= 0)
    description = serializers.CharField(
        max_length = 1000,
        allow_blank= True, 
        required = False,
    ) 
    filter = FilterSerializer(required=True)
    created_date=serializers.DateTimeField(read_only=True)
    killed_date=serializers.DateTimeField(read_only=True)
    
    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Le nom ne peut pas être vide")
        return value.strip()
    
    def validate_status(self, value):
        """Valide le statut (0=inactif, 1=actif, 2=pause)"""
        valid_statuses = [0, 1, 2]
        if value not in valid_statuses:
            raise serializers.ValidationError(f"Status doit être parmi {valid_statuses}")
        return value
    
    def create(self, validated_data):
        """Méthode pour créer (géré dans la vue)"""
        return validated_data
    
    def update(self, instance, validated_data):
        """Méthode pour mettre à jour (géré dans la vue)"""
        return validated_data

# class BotSerializer(serializers.ModelSerializer):
#     filter=BotFilterSerializer()
#     class Meta:
#         model = Bots
#         fields = ['id_bot', 'name','status','assigned_user','assigned_user_id','descritpion','filter']
#         read_only_fields = ['id_bot']
        
#     def create(self, validated_data):
#         bot_filter_data = validated_data.pop('filter')
#         with transaction.atomic():
#             bot = Bots.objects.create(**validated_data)
#             bot_filter_serializer = BotFilterSerializer(data=bot_filter_data, context={'bot': bot})
#             bot_filter_serializer.is_valid(raise_exception=True)
#             bot_filter_serializer.save()
#         return bot
