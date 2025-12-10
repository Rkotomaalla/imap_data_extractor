from rest_framework import serializers

class MailSerializer(serializers.Serializer):
    id=serializers.CharField(read_only=True)
    mail_id = serializers.IntegerField(read_only=True) 
    subject = serializers.CharField (      
        max_length = 1000,
        allow_blank=False, 
        required = True,
    ) 
    sender=serializers.EmailField(
        required =True,
        error_messages={
            'required': 'L\'email est obligatoire',
            'invalid': 'Format d\'email invalide'
        }
    )
    date=serializers.DateTimeField(required=True)
    saved_date=serializers.DateTimeField(read_only=True)
    body=serializers.CharField(required=True)
