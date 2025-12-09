from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta


def generate_bot_token(bot_id):
    token = AccessToken()
    token.set_exp(lifetime=timedelta(days=30))  # token valide 30 jours
    token["is_bot"] = True
    token["bot_id"] = str(bot_id)
    return str(token)