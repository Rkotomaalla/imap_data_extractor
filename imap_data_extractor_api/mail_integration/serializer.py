from rest_framework import serializers

class OutlookConfSerializer(serializers.Serializer):
    conf_id = serializers.IntegerField(read_only=True)
    id = serializers.CharField(read_only=True)

    user_id = serializers.IntegerField(
        required=True,
        error_messages={
            'required': "L'id de l'utilisateur est obligatoire",
            'invalid': "L'id de l'utilisateur doit être un nombre"
        }
    )

    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': "L'email de l'utilisateur est obligatoire",
            'invalid': "Email invalide"
        }
    )

    created_date = serializers.DateTimeField(read_only=True)
    updated_date = serializers.DateTimeField(read_only=True)
