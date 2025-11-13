import logging
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from .services.ldap_service import LDAPService

logger = logging.getLogger(__name__)
User = get_user_model()

class LDAPAuthenticationBackend(BaseBackend):
    """
    Backend d'authentification personnalisé utilisant LDAP.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authentifie un utilisateur via LDAP et synchronise avec Django.
        
        Args:
            request: Requête HTTP
            username: Nom d'utilisateur
            password: Mot de passe
            
        Returns:
            User: Instance utilisateur Django ou None
        """
        
        if not username or not password:
            return None
        
        # Authentifier via LDAP
        ldap_service = LDAPService()
        ldap_user_info = ldap_service.authenticate_user(username, password)
        
        if not ldap_user_info:
            logger.warning(f"Échec authentification LDAP pour: {username}")
            return None
        # Synchroniser avec Django
        try:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': ldap_user_info.get('email', ''),
                    'first_name': ldap_user_info.get('first_name', ''),
                    'last_name': ldap_user_info.get('last_name', ''),
                    'ldap_dn': ldap_user_info.get('dn', ''),
                    'ldap_roles': ldap_user_info.get('roles', []),
                }
            )
            if not created:
                # Mettre à jour les informations
                user.email = ldap_user_info.get('email', user.email)
                user.first_name = ldap_user_info.get('first_name', user.first_name)
                user.last_name = ldap_user_info.get('last_name', user.last_name)
                user.ldap_dn = ldap_user_info.get('dn', user.ldap_dn)
                user.ldap_roles = ldap_user_info.get('roles', [])
                user.save()
            
            logger.info(f"Utilisateur Django {'créé' if created else 'mis à jour'}: {username}")
            return user
            
        except Exception as e:
            logger.error(f"Erreur lors de la synchronisation utilisateur: {e}")
            return None
        
    def get_user(self, user_id):
        """
        Récupère un utilisateur par son ID.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    