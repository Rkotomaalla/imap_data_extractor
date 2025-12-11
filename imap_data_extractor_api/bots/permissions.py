# bots/permissions.py
import logging
from rest_framework.permissions import BasePermission

logger = logging.getLogger(__name__)

class IsBot(BasePermission):
    """
    Permission : uniquement les Bots identifiés par un JWT spécial
    """
    message = "Seuls les bots autorisés peuvent effectuer cette action."
    
    def has_permission(self, request, view):
        token = getattr(request, "auth", None)
        
        if not token:
            logger.warning("Tentative d'accès sans token")
            return False
        
        logger.info(f"Vérification permission BOT : token = {token.payload}")
        
        is_bot = token.get("is_bot", False)
        bot_id = token.get("bot_id", None)
        assigned_user_id = token.get("assigned_user_id",None)
        if not is_bot:
            logger.warning("Token sans claim 'is_bot'")
            return False
        
        if not bot_id:
            logger.warning("Token bot sans 'bot_id'")
            return False
        
        if not assigned_user_id:
            logger.warning("Token bot sans 'assigned_user_id'")
            return False
        
        logger.info(f"✅ Bot autorisé : {bot_id}")
        return True

    
    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)



