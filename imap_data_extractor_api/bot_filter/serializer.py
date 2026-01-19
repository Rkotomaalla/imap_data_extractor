from rest_framework import serializers
# from .models import BotFilter,Field,Operator,BotRule
from django.conf import settings
from configurations.services import mongo_service

from configurations.services import mongo_service

from configurations.services import mongo_service

class RuleSerializer(serializers.Serializer):
    field_id = serializers.IntegerField(min_value=1,required=True)
    operator_id = serializers.IntegerField(min_value = 1 , required = True)
    value = serializers.CharField(max_length = 500)
    
    def validate_field_id(self, value):
        """valid si le field_existe Vraiment"""
        # Vefirication dans mongoDb
        field_collection =mongo_service.get_collection('field')
        field_exists = field_collection.find_one({"field_id": int(value)})
        if not field_exists: 
            raise serializers.ValidationError(f"field_id {value} n'existe pas")
        return value
    

    def validate_operator_id(self,value):
        """Verification si l operator existe vraiment"""
        operator_collection = mongo_service.get_collection('operator')
        operator_exists = operator_collection.find_one({'operator_id' : int(value)})
        if not operator_exists:
            raise serializers.ValidationError(f"operator_id {value} n'existe pas") 
        return value
    
    def validate(self,data):
        """vérifie que operator_id appartient bien à field_id"""
        field_id= data.get('field_id')
        operator_id=data.get('operator_id')       
        
        operator_collection = mongo_service.get_collection('operator')
        
        operator_doc = operator_collection.find_one({
            'operator_id': operator_id,
            'field_id': field_id
        })
        
        if not operator_doc:
            raise serializers.ValidationError({
                'operator_id' : f"L'opérateur {operator_id} n'appartient pas au champ {field_id}"
            }) 
        return data
        
        

    
        
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
# eto ny manaraka
# ===================================================================================================


class FieldsSerializer(serializers.Serializer):
    """Serializer"""
    field_id = serializers.IntegerField(read_only = True)
    id = serializers.CharField(read_only=True)
    field_name = serializers.CharField(required = True)
    type = serializers.CharField(required=True)
    is_indexed = serializers.BooleanField(required=True)
    operators  = serializers.ListField(
        child=serializers.IntegerField(),     # par défaut
        allow_null = True
    )

class OperatorsSerializer(serializers.Serializer):
    """operators"""
    operator_id = serializers.IntegerField(read_only= True)
    id = serializers.CharField(read_only = True)
    label =  serializers.CharField(required=True)
    many = serializers.BooleanField(required = True)
    value_type =  serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    
class RulesSerializer(serializers.Serializer):
    """Serailizer"""
    field_id = serializers.IntegerField(min_value=1,required=True)
    operator_id = serializers.IntegerField(min_value = 1 , required = False)
    value = serializers.JSONField( required=False, allow_null=True, default=dict)
    
    def validate_field_id(self, value):
        """valid si le field_existe Vraiment"""
        # Vefirication dans mongoDb
        field_collection =mongo_service.get_collection('fields')
        field_exists = field_collection.find_one({"field_id": int(value)})
        if not field_exists: 
            raise serializers.ValidationError(f"field_id {value} n'existe pas")
        return value
    
    def validate_operator_id(self,value):
        """Verification si l operator existe vraiment"""
        operator_collection = mongo_service.get_collection('operators')
        operator_exists = operator_collection.find_one({'operator_id' : int(value)})
        if not operator_exists:
            raise serializers.ValidationError(f"operator_id {value} n'existe pas") 
        return value

    
    def validate(self, data):
        """
        Validation personnalisée :
        - Vérifie que 'value' contient bien une clé 'value'
        - Si le field n'est pas indexé → operator_id est obligatoire + doit exister dans la liste
        - Si l'opérateur accepte plusieurs valeurs ("many") → value.value doit être une liste
        """
        field_id = data.get('field_id')
        operator_id = data.get('operator_id')
        value_dict = data.get('value')  # c'est censé être un dictionnaire

        # 1. Vérification de base : la structure value
        if not isinstance(value_dict, dict):
            raise serializers.ValidationError({
                'value': "Le champ 'value' doit être un objet/dictionnaire"
            })

        if 'value' not in value_dict or value_dict['value'] is None:
            raise serializers.ValidationError({
                'value': f"La clé 'value' est obligatoire et ne peut pas être vide pour le champ {field_id}"
            })

        # -------------------------------------------------------------------------
        # Si on n'a pas besoin de vérifier les opérateurs (champ non indexé)
        # -------------------------------------------------------------------------
        field_collection = mongo_service.get_collection("fields")
        field_doc = field_collection.find_one({"field_id": field_id})

        if not field_doc:
            raise serializers.ValidationError({
                'field_id': f"Le champ avec field_id={field_id} n'existe pas"
            })

        # Cas où le champ n'est PAS indexé
        if not field_doc.get("is_indexed", False):  # ← clé corrigée (is_indexed)
            # operator_id devient obligatoire
            if operator_id is None:
                raise serializers.ValidationError({
                    'operator_id': f"L'opérateur est obligatoire pour le champ {field_id}"
                })

            operators = field_doc.get("operators", [])
            if operator_id not in operators:
                raise serializers.ValidationError({
                    'operator_id': f"L'opérateur {operator_id} n'est pas autorisé pour ce champ "
                                f"(opérateurs valides : {operators})"
                })

            # Vérification des propriétés de l'opérateur
            operator_collection = mongo_service.get_collection("operators")
            operator_doc = operator_collection.find_one({"operator_id": operator_id})

            if not operator_doc:
                raise serializers.ValidationError({
                    'operator_id': f"L'opérateur {operator_id} n'existe pas en base"
                })

            # Si l'opérateur accepte plusieurs valeurs ("many")
            if operator_doc.get("many", False):
                real_value = value_dict["value"]
                if not isinstance(real_value, (list, tuple)):
                    raise serializers.ValidationError({
                        'value': f"Pour l'opérateur {operator_id} (many=true), la valeur doit être un tableau"
                    })

                if not real_value:  # liste vide
                    raise serializers.ValidationError({
                        'value': f"La liste de valeurs ne peut pas être vide pour l'opérateur {operator_id}"
                    })
        else:
            if operator_id : 
                    raise serializers.ValidationError({
                        'operator_id': f"l operator_id n est pas valide pour le field {field_id} car c est une index"
                    })
        # -------------------------------------------------------------------------
        # Tout est ok → on retourne les données validées
        # -------------------------------------------------------------------------
        return data
    
            
class FilterSerializer(serializers.Serializer):
    """Filter Principal"""
    name = serializers.CharField(max_length=255,required=True)
    required_all = serializers.BooleanField(default=True)
    action = serializers.IntegerField(min_value=0 , max_value= 10)
    rules = RulesSerializer(many=True,allow_empty=False)
    
    def validate_rules(self , value) :
        """valide qu il y a une regle"""
        if not value: 
            raise serializers.ValidationError("Il doit y avoir au moins une regle")
        return value
