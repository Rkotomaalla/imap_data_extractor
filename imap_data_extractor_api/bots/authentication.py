# bots/authentication.py
import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

logger = logging.getLogger(__name__)

class BotJWTAuthentication(JWTAuthentication):
    """
    Authentification JWT personnalisée qui accepte les tokens BOT sans user_id
    """
    def get_user(self, validated_token):
        """
        Gérer les tokens BOT qui n'ont pas de user_id
        """
        is_bot = validated_token.get("is_bot", False)
        if is_bot:
            bot_id = validated_token.get("bot_id")
            logger.info(f"🤖 Token BOT détecté : bot_id={bot_id}")
            return None  # Pas d'utilisateur pour les bots
        
        # Pour les tokens utilisateurs normaux
        try:
            return super().get_user(validated_token)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {e}")
            raise InvalidToken("Token ne contient pas d'identification utilisateur valide")

    def authenticate(self, request):
        """
        Permettre l'authentification sans utilisateur pour les bots
        """
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
        except TokenError as e:
            logger.warning(f"Token invalide: {e}")
            raise InvalidToken(e.args[0])
        
        user = self.get_user(validated_token)
        return (user, validated_token)
