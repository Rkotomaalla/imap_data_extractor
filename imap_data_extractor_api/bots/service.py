from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta


def generate_bot_token(bot_id,assigned_user_id):
    """
    Génère un token JWT spécial pour un bot
    """
    token = AccessToken()
    token.set_exp(lifetime=timedelta(days=30))  # token valide 30 jours
    
    # Claims personnalisés pour identifier le bot
    token["is_bot"] = True
    token["bot_id"] = str(bot_id)
    token["assigned_user_id"] = str(assigned_user_id)
    token["type"] = "bot_access"
    
    # ⚠️ NE PAS ajouter user_id pour les bots
    # L'authentification personnalisée gère ce cas
    
    return str(token)