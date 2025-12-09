from rest_framework.permissions import BasePermission
import logging
logger = logging.getLogger(__name__)

class IsBot(BasePermission):
    """
    Permission : uniquement les Bots identifiés par un JWT spécial
    """
    def has_permission(self, request, view):

        token = request.auth  # SimpleJWT stocke le payload ici

        if not token:
            return False
        
        logger.info(f"Vérification permission BOT : token = {token}")
        
        # Vérifier que le token est bien un BOT token
        is_bot = token.get("is_bot", False)
        bot_id = token.get("bot_id", None)
    
        # Vérifie que bot_id est présent et valide
        return is_bot is True and bot_id is not None

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)