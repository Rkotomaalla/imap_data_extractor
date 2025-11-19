from rest_framework.permissions import BasePermission
import logging

logger=logging.getLogger(__name__)

class IsAdmin(BasePermission):
    """
    Permission personnalisée : seuls les admins peuvent accéder
    """
    
    def  has_permission(self, request, view):
        
        if not request.user or not request.user.is_authenticated:
            return False
        logger.info(f"Vérification des permissions pour l'utilisateur avec le rôle: {request.user.ldap_role}")
        
        user_role = getattr(request.user, 'ldap_role', None)
        return user_role == 'admin'
    
    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)
    