from rest_framework import serializers
from .models import Bots
from django.db import transaction
from bot_filter.serializer import BotFilterSerializer
class BotSerializer(serializers.ModelSerializer):
    filter=BotFilterSerializer()
    class Meta:
        model = Bots
        fields = ['id_bot', 'name','status','assigned_user','assigned_user_id','descritpion','filter']
        read_only_fields = ['id_bot']
        
    def create(self, validated_data):
        bot_filter_data = validated_data.pop('filter')
        with transaction.atomic():
            bot = Bots.objects.create(**validated_data)
            bot_filter_serializer = BotFilterSerializer(data=bot_filter_data, context={'bot': bot})
            bot_filter_serializer.is_valid(raise_exception=True)
            bot_filter_serializer.save()
        return bot
