from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class LoginSerializer(serializers.Serializer):
    """Serializer pour la requête de login"""
    username = serializers.CharField(
        max_length=150,
        required=True,
        help_text="Nom d'utilisateur LDAP"
    )
    password = serializers.CharField(
        max_length=128,
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Mot de passe LDAP"
    )
    
    def validate_username(self, value):
        """Validation du username"""
        if not value.strip():
            raise serializers.ValidationError("Le username ne peut pas être vide")
        return value.strip()
    
    def validate_password(self, value):
        """Validation du password"""
        if len(value) < 3:
            raise serializers.ValidationError("Le mot de passe est trop court")
        return value
    
class UserSerializer(serializers.ModelSerializer):
    """Serializer pour les informations utilisateur"""
    roles = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'ldap_dn',
            'roles',
            'last_ldap_sync',
            'date_joined',
            'is_active'
        ]
        read_only_fields = ['id', 'date_joined', 'last_ldap_sync']

    def get_roles(self, obj):
        """Retourne les rôles LDAP"""
        return obj.ldap_roles if hasattr(obj, 'ldap_roles') else []


class LoginResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de login"""
    success = serializers.BooleanField()
    message = serializers.CharField()
    user = UserSerializer(required=False)
    session_id = serializers.CharField(required=False)