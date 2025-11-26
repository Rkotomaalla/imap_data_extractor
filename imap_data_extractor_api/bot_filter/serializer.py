from rest_framework import serializers
from .models import BotFilter,Field,Operator,BotRule


    
class BotRuleSerializer(serializers.ModelSerializer):
    # field = serializers.PrimaryKeyRelatedField(queryset=Field.objects.all())
    # operator = serializers.PrimaryKeyRelatedField(queryset=Operator.objects.all())
    
        # Ici on attend l'id directement, pas l'objet Django
    field_id = serializers.IntegerField()
    operator_id = serializers.IntegerField()
    
    class Meta:
        model=BotRule
        fields = ['id_rule', 'field_id', 'operator_id', 'value']
        read_only_fields = ['id_rule']
        
    def validate(self, data):
        # field = data.get('field')
        # operator = data.get('operator')                
          # Récupérer les objets depuis la base selon l'id
        field = Field.objects.get(id_field=data['field_id'])
        operator = Operator.objects.get(id_operator=data['operator_id'])
        if operator.field != field:
            raise serializers.ValidationError("Cet opérateur n'appartient pas au field sélectionné.")
        return data
    
    
    
class BotFilterSerializer(serializers.ModelSerializer):
    rules=BotRuleSerializer(many=True)
    class Meta:
        model=BotFilter
        fields=['id_filter','name','required_all','action','rules']
        read_only_fields=['id_filter']    
        
    def create(self, validated_data):
        rules_data = validated_data.pop('rules', [])
        bot = self.context.get('bot')  # on reçoit le Bot depuis le serializer parent
        bot_filter = BotFilter.objects.create(bot=bot, **validated_data)
        for rule_data in rules_data:
            BotRule.objects.create(bot_filter=bot_filter, **rule_data)
        return bot_filter