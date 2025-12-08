from rest_framework import serializers
# from .models import BotFilter,Field,Operator,BotRule
from django.conf import settings






class RuleSerializer(serializers.Serializer):
    field_id = serializers.IntegerField(min_value=1,required=True)
    operator_id = serializers.IntegerField(min_value = 1 , required = True)
    value = serializers.CharField(max_length = 500)
    
    def validate_field_id(self, value):
        """valid si le field_existe Vraiment"""
        # Vefirication dans mongoDb
        field_collection = settings.MONGO_COLLECTIONS.get('fields', settings.MONGO_DB['field'])
        field_exists = field_collection.find_one({"field_id": int(value)})
        if not field_exists: 
            raise serializers.ValidationError(f"field_id {value} n'existe pas")
        return value
    

    def validate_operator_id(self,value):
        """Verification si l operator existe vraiment"""
        operator_collection = settings.MONGO_COLLECTIONS.get('operators', settings.MONGO_DB['operator'])
        operator_exists = operator_collection.find_one({'operator_id' : int(value)})
        if not operator_exists:
            raise serializers.ValidationError(f"operator_id {value} n'existe pas") 
        return value
    
    def validate(self,data):
        """vérifie que operator_id appartient bien à field_id"""
        field_id= data.get('field_id')
        operator_id=data.get('operator_id')       
        
        operator_collection = settings.MONGO_COLLECTIONS.get('operators', settings.MONGO_DB['operator'])
        
        operator_doc = operator_collection.find_one({
            'operator_id': operator_id,
            'field_id': field_id
        })
        
        if not operator_doc:
            raise serializers.ValidationError({
                'operator_id' : f"L'opérateur {operator_id} n'appartient pas au champ {field_id}"
            }) 
        return data
        
        
class FilterSerializer(serializers.Serializer):
    """Filter Principal"""
    name = serializers.CharField(max_length=255,required=True)
    required_all = serializers.BooleanField(default=True)
    action = serializers.IntegerField(min_value=0 , max_value= 10)
    rules = RuleSerializer(many=True,allow_empty=False)
    
    def validate_rules(self , value) :
        """valide qu il y a une regle"""
        if not value: 
            raise serializers.ValidationError("Il doit y avoir au moins une regle")
        return value

    
        
class FieldSerializer(serializers.Serializer):
    """Field"""
    field_id = serializers.IntegerField(read_only=True)
    id = serializers.CharField(read_only = True)
    name = serializers.CharField(max_length = 200 , required = True)    
    
    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Le nom ne peut pas être vide")
        return value.strip()
    
    
class OperatorSerializer(serializers.Serializer):
    """Operator"""
    operator_id = serializers.IntegerField(read_only=True)
    id = serializers.CharField(read_only = True)
    field_id = serializers.IntegerField(min_value = 1 , required = True)
    name = serializers.CharField(max_length = 200 , required = True)    
    
    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Le nom ne peut pas être vide")
        return value.strip()
    def validate_field_id(self, value):
        if not value:
            raise serializers.ValidationError("L id du Field  ne peut pas être vide")
        return value
            
# ==========================================================================================================================================================================================================================================================
    
# class BotRuleSerializer(serializers.ModelSerializer):
#     # field = serializers.PrimaryKeyRelatedField(queryset=Field.objects.all())
#     # operator = serializers.PrimaryKeyRelatedField(queryset=Operator.objects.all())
    
#         # Ici on attend l'id directement, pas l'objet Django
#     field_id = serializers.IntegerField()
#     operator_id = serializers.IntegerField()
    
#     class Meta:
#         model=BotRule
#         fields = ['id_rule', 'field_id', 'operator_id', 'value']
#         read_only_fields = ['id_rule']
        
#     def validate(self, data):
#         # field = data.get('field')
#         # operator = data.get('operator')                
#           # Récupérer les objets depuis la base selon l'id
#         field = Field.objects.get(id_field=data['field_id'])
#         operator = Operator.objects.get(id_operator=data['operator_id'])
#         if operator.field != field:
#             raise serializers.ValidationError("Cet opérateur n'appartient pas au field sélectionné.")
#         return data
    
    
    
# class BotFilterSerializer(serializers.ModelSerializer):
#     rules=BotRuleSerializer(many=True)
#     class Meta:
#         model=BotFilter
#         fields=['id_filter','name','required_all','action','rules']
#         read_only_fields=['id_filter']    
        
#     def create(self, validated_data):
#         rules_data = validated_data.pop('rules', [])
#         bot = self.context.get('bot')  # on reçoit le Bot depuis le serializer parent
#         bot_filter = BotFilter.objects.create(bot=bot, **validated_data)
#         for rule_data in rules_data:
#             BotRule.objects.create(bot_filter=bot_filter, **rule_data)
#         return bot_filter