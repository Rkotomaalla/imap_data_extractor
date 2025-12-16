from rest_framework_simplejwt.authentication import JWTAuthentication

class CustomJWTAuthentication(JWTAuthentication):   
    """
    Authentication JWT personnalisée pour extraire le rôle du token
    """
    
    def authenticate(self, request):
        """
        Authentifie l'utilisateur et ajoute le rôle LDAP à l'objet user.
        """
        header= self.get_header(request)
        if header is None:
            return None
        
        raw_token =  self.get_raw_token(header)
        
        if raw_token is None:
            return None
        
        validated_token = self.get_validated_token(raw_token)
        user = self.get_user_from_token(validated_token)
        
        return (user, validated_token)
    
    def get_user_from_token(self, validated_token):
        """
        Créer un objet utilisateur à partir du token JWT
        """
        from types import SimpleNamespace
        
        username = validated_token.get('username', '')
        email = validated_token.get('email', '')
        ldap_dn = validated_token.get('ldap_dn','')
        uid_number = validated_token.get('uid_number')
        role = validated_token.get('role', 'user')
        user = SimpleNamespace(
            uid_number=uid_number,
            email=email,
            username=username,
            ldap_dn=ldap_dn,
            ldap_role=role,
            is_authenticated=True,
            is_active=True
        )
        
        return user