import logging
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from .services.ldap_service import LDAPService
from django.db import IntegrityError
logger = logging.getLogger(__name__)
User = get_user_model()

class LDAPAuthenticationBackend(BaseBackend):
    """
    Backend d'authentification personnalisé utilisant LDAP.
    """
    def authenticate(self, request,email=None,password=None, **kwargs):
        """
        Authentifie un utilisateur via LDAP et synchronise avec Django.
        
        Args:
            request: Requête HTTP
            username: Nom d'utilisateur
            password: Mot de passe
            
        Returns:
            User: Instance utilisateur Django ou None
        """
        
        ldap_service = LDAPService()
        
        if not email or not password:
            logger.warning("Username ou password manquant")
            return None
        
        # Authentifier via LDAP
        ldap_service = LDAPService()
        ldap_user_info = ldap_service.authenticate_user(email, password)
        
        if not ldap_user_info:
            logger.warning(f"Échec authentification LDAP pour: {email}")
            return None
        # Synchroniser avec Django
        try:
            # Préparer les données utilisateur
            user_data = {
                'email': ldap_user_info.get('email', ''),
                'first_name': ldap_user_info.get('first_name', ''),
                'last_name': ldap_user_info.get('last_name', ''),
            }
            # Ajouter les champs LDAP seulement s'ils existent dans le modèle
            if hasattr(User, 'ldap_dn'):
                user_data['ldap_dn'] = ldap_user_info.get('dn', '')
            if hasattr(User,'ldap_role'):
                user_data['ldap_role']=ldap_user_info.get('role','')
            if hasattr(User, 'ldap_roles'):
                user_data['ldap_roles'] = ldap_user_info.get('roles', [])
                
            # Créer ou récupérer l'utilisateur
            user, created = User.objects.get_or_create(
                username=ldap_user_info['username'],
                defaults=user_data
            )
            
            if not created:
                # Mettre à jour les informations existantes
                for field, value in user_data.items():
                    setattr(user, field, value)
                user.save()
            
            logger.info(f"Utilisateur Django {'créé' if created else 'mis à jour'}: {email}")
            return user
        
        except IntegrityError as e:
            logger.error(f"❌ Erreur d'intégrité DB pour {email}: {e}")
            return None
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
            logger.debug(f"Utilisateur {user_id} introuvable")
            return None
    