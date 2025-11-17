from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer JWT personnalisé pour inclure les infos LDAP.
    """    
    @classmethod
    def get_token(cls, user):
        """
        Ajoute des claims personnalisés au token.
        """
        token  = super().get_token(user)
        
         # Claims standards
        token['username'] = user.username
        token['email'] = user.email
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        
        # Claims LDAP spécifiques
        token['ldap_dn'] = user.ldap_dn if hasattr(user, 'ldap_dn') else ''
        
        # Rôles LDAP
        if hasattr(user, 'ldap_roles'):
            token['roles'] = [role.get('name') for role in user.ldap_roles]
        else:
            token['roles'] = []
        
        return token

    def validate(self, attrs):
        """
         Validation personnalisée avec authentification LDAP.
        """
        data =  super().validate(attrs)
        
        # Ajouter les informations utilisateur dans la réponse
        data['user'] = UserSerializer(self.user).data
        
        return data
    
    
    
class LoginSerializer(serializers.Serializer):
    """Serializer pour la requête de login"""
    email = serializers.EmailField(
        required=True,
        help_text="Adresse email de l'utilisateur LDAP"
    )
    # username = serializers.CharField(
    #     max_length=150,
    #     required=True,
    #     help_text="Nom d'utilisateur LDAP"
    # )
    password = serializers.CharField(
        max_length=128,
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Mot de passe LDAP"
    )
    
    def validate_email(self, value):
        """Validation par Email"""
        if not value or not value.strip():
            raise serializers.ValidationError("L'email ne peut pas être vide")
        # Normaliser l'email (minuscules)
        return value.strip().lower()
    # def validate_username(self, value):
    #     """Validation du username"""
    #     if not value.strip():
    #         raise serializers.ValidationError("Le username ne peut pas être vide")
    #     return value.strip()
    
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

# fonction de get Role[0]
    def get_role(self,obj):
        """Retourne le rôle LDAP indice 0"""
        return obj.ldap_role if hasattr(obj, 'ldap_role') else ''
    
    def get_roles(self, obj):
        """Retourne les rôles LDAP"""
        return obj.ldap_roles if hasattr(obj, 'ldap_roles') else []


class LoginResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de login"""
    success = serializers.BooleanField()
    message = serializers.CharField()
    user = UserSerializer(required=False)
    access = serializers.CharField(help_text="JWT Access Token (15 min)")
    refresh = serializers.CharField(help_text="JWT Refresh Token (7 jours)")
    
    
