from rest_framework import serializers
class MongoConfigSerializer(serializers.Serializer):
    id = serializers.CharField(
        read_only=True,
        help_text="C est l object Id fournit par mongoDb"
    )
    conf_id = serializers.IntegerField(
        read_only = True,
        help_text = "C est l id generer par mon code"
    )
    name = serializers.CharField(
        max_length= 100,
        default  =  "default",
        help_text = "UNe sorte de nom de cette ligne"
    )
    host = serializers.CharField(
        max_length=255,
        required=True,
        help_text="Adresse du serveur MongoDB (ex: 'localhost' ou 'mongodb://host:port')"
    )
    port = serializers.IntegerField(
        required=True,
        min_value=1,
        max_value=65535,
        help_text="Port du serveur MongoDB"
    )
    db_name = serializers.CharField(
        max_length=100,
        required=True,
        help_text="Nom de la base de données MongoDB"
    )
    username = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        help_text="Nom d'utilisateur MongoDB (optionnel)"
    )
    password = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        help_text="Mot de passe MongoDB (optionnel)"
    )
    version = serializers.IntegerField(
        read_only=True,
        help_text="Version de la configuration"
    )
    is_acticve = serializers.BooleanField(
        default = True,
        help_text = "C est ca qui assure quelle configuration est activée"
    )
    updated_at = serializers.DateTimeField(
        read_only=True,
        help_text="Date de dernière mise à jour"
    )
    created_by = serializers.IntegerField(
        required = True,
        help_text = "L id de l utilisateur responsable du changement"
    )
    change_reason =  serializers.CharField(
        max_length = 1200,
        help_text ="Raison de cette nouvelle version de configuration"
    )
    
    def validate_host(self, value):
        if not value.startswith("mongodb://") and value != "localhost":
            # Optionnel : vérifier le format correct de l'URL MongoDB
            value = f"mongodb://{value}"
        return value
