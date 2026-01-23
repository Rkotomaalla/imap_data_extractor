from rest_framework import serializers
# from .models import Bots
from django.db import transaction
from bot_filter.serializer import FilterSerializer
from django.conf import settings


    

class BotSerializer(serializers.Serializer):
    bot_id = serializers.IntegerField(read_only=True)
    id = serializers.CharField(read_only = True)
    name = serializers.CharField(max_length = 200 , required = True)    
    status = serializers.IntegerField(min_value=0, max_value =  3 , default= 2)
    description = serializers.CharField(
        max_length = 1000,
        allow_blank= True, 
        required = False,
    ) 
    filter = FilterSerializer(required=False)
    created_date=serializers.DateTimeField(read_only=True)
    killed_date=serializers.DateTimeField(read_only=True)
    assigned_user_id=serializers.IntegerField(read_only=True)
    
    
    def validate(self, attrs):
        # Si c'est une création
        if self.instance is None:
            required_on_create = ["name", "filter"]
            missing = [field for field in required_on_create if field not in attrs or attrs[field] in [None, ""]]
            if missing:
                raise serializers.ValidationError(
                    {field: "Ce champ est requis lors de la création." for field in missing}
                )

        # Validation supplémentaire pour name si présent
        if "name" in attrs and not attrs["name"].strip():
            raise serializers.ValidationError({"name": "Le nom ne peut pas être vide"})

        return attrs

    def validate_name(self, value):
        if value is not None and not value.strip():
            raise serializers.ValidationError("Le nom ne peut pas être vide")
        return value.strip() if value else value

    
    def validate_status(self, value):
        """Valide le statut (0=inactif, 1=actif, 2=pause)"""
        valid_statuses = [0, 1, 2,3]
        if value not in valid_statuses:
            raise serializers.ValidationError(f"Status doit être parmi {valid_statuses}")
        return value
    
    def create(self, validated_data):
        """Méthode pour créer (géré dans la vue)"""
        return validated_data
    
    def update(self, instance, validated_data):
        """Méthode pour mettre à jour (géré dans la vue)"""
        return validated_data



class BotArchiveSerializer(serializers.Serializer):
    id=serializers.CharField(read_only =True)
    bot_archive_id = serializers.IntegerField(read_only = True)
    deleted_by = serializers.IntegerField(read_only =  True)
    deleted_at = serializers.DateTimeField(read_only = True)
    bot_id=serializers.IntegerField(required=True)
    bot = BotSerializer(required=True)
    
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
