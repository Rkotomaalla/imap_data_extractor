from rest_framework import serializers

class UserSerializer(serializers.Serializer):
    first_name = serializers.CharField(
        required=True,
        error_messages={
            'required': 'Le prénom est obligatoire',
            'blank': 'Le prénom ne peut pas être vide'
        }
    )
    
    last_name = serializers.CharField(
        max_length=100,
        required=True,
        error_messages={
            'required': 'Le nom est obligatoire',
            'blank': 'Le nom ne peut pas être vide'
        }
    )
    
    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': 'L\'email est obligatoire',
            'invalid': 'Format d\'email invalide'
        }
    )
    
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        required=True,
        style={'input_type': 'password'},
        error_messages={
            'required': 'Le mot de passe est obligatoire',
            'min_length': 'Le mot de passe doit contenir au moins 8 caractères'
        }
    )
    
    
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        error_messages={
            'required': 'La confirmation du mot de passe est obligatoire'
        }
    )
    
    role = serializers.ChoiceField(
        choices=['admin', 'user', 'manager', 'guest'],
        required=True,
        error_messages={
            'required': 'Le rôle est obligatoire',
            'invalid_choice': 'Rôle invalide'
        }
    )
    
    departement = serializers.CharField(
        max_length=100,
        required=True,
        error_messages={
            'required': 'Le département est obligatoire',
            'blank': 'Le département ne peut pas être vide'
        }
    )
    
    def  validate(self,data):
        """Validation globale des données"""
        # Vérifier que les mots de passe correspondent
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Les mots de passe ne correspondent pas'
            })
        
        # Supprimer confirm_password avant de retourner les données
        data.pop('confirm_password')
        
        return data
    
    
    def validate_email(self, value):
        """Validation spécifique de l'email"""
        return value.lower()
    
    
    
class UserUpdateSerializer(serializers.Serializer):
    
    email = serializers.EmailField(
        allow_null=True,
        required=False,
    )
    
    current_password = serializers.CharField(
        allow_null=True,
        write_only=True,
        required=False,
        style={'input_type': 'password'},
    )
    new_password = serializers.CharField(
        allow_null=True,
        write_only=True,
        min_length=8,
        required=False,
        style={'input_type': 'password'},
        error_messages={
            'required': 'Le mot de passe est obligatoire',
            'min_length': 'Le mot de passe doit contenir au moins 8 caractères'
        }
    )
    
    confirm_password = serializers.CharField(
        allow_null=True,
        write_only=True,
        required=False,
        style={'input_type': 'password'},
    )
    
    role = serializers.ChoiceField(
        allow_null=True,
        choices=['admin', 'user', 'manager', 'guest'],
        required=False,
    )
    
    departement = serializers.CharField(
        allow_null=True,
        max_length=100,
        required=False,
    )
    
    def  validate(self,data):
        """Validation globale des données"""
        # Si un mot de passe est fourni, vérifier qu'il correspond à la confirmation
        if 'new_password' in data:
            if 'current_password' not in data or not data['current_password']:
                raise serializers.ValidationError({
                    'Current password': 'Le mot de passe actuel est obligatoire'
                })
            if data['new_password'] != data['confirm_password']:
                raise serializers.ValidationError({
                    'confirm_password': 'Les mots de passe ne correspondent pas'
                })
        
        # Supprimer confirm_password avant de retourner les données
        data.pop('confirm_password', None)
        
        return data
    
    def validate_email(self, value):
        """Validation spécifique de l'email"""
        return value.lower() if value else value