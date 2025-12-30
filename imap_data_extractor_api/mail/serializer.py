# from rest_framework import serializers

# class MailSerializer(serializers.Serializer):
#     # id=serializers.CharField(read_only=True)
#     # mail_id = serializers.IntegerField(read_only=True) 
#     # subject = serializers.CharField (      
#     #     max_length = 1000,
#     #     allow_blank=False, 
#     #     required = True,
#     # ) 
#     # sender=serializers.EmailField(
#     #     required =True,
#     #     error_messages={        
#     #         'required': 'L\'email est obligatoire',
#     #         'invalid': 'Format d\'email invalide'
#     #     }
#     # )
#     # date=serializers.DateTimeField(required=True)
#     # saved_date=serializers.DateTimeField(read_only=True)
#     # body=serializers.CharField(required=True)

from rest_framework import serializers
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime




    
# class EmailFilterSerializer(serializers.Serializer):
#     has_attachment= serializers.BooleanField(required=False)
#     received_date=serializers.DateTimeField(required=False,default = None)
#     date =  serializers.DateTimeField(required=False)
#     status = serializers.ChoiceField(
#         required=False,
#         choices = ["read", "unread"]
#     )
class EmailFilterSerializer(serializers.Serializer):
    has_attachment = serializers.BooleanField(required=False, allow_null=True, default=None)
    received_date = serializers.DateTimeField(required=False, allow_null=True, default=None)
    date = serializers.DateTimeField(required=False, allow_null=True, default=None)
    status = serializers.ChoiceField(
        required=False,
        allow_null=True,
        default=None,
        choices=["read", "unread"]
    )
# Définis les énumérations (à placer dans un fichier séparé si nécessaire)
class EmailPriority(Enum):
    URGENT = "urgent"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"

class EmailStatus(Enum):
    UNREAD = "unread"
    READ = "read"
    ARCHIVED = "archived"
    FLAGGED = "flagged"
    SPAM = "spam"
    TRASH = "trash"

# Sérialiseur pour EmailAddress
class EmailAddressSerializer(serializers.Serializer):
    email = serializers.EmailField()
    name = serializers.CharField(required=False, allow_null=True)
    
# Sérialiseur pour EmailAttachment
class EmailAttachmentSerializer(serializers.Serializer):
    filename = serializers.CharField(required=False, allow_null=True)
    content_type = serializers.CharField(required=False, allow_null=True)
    size = serializers.IntegerField(required=False, allow_null=True)
    attachment_id = serializers.CharField(required=False, allow_null=True)


# Sérialiseur principal pour EmailEvent
class MailSerializer(serializers.Serializer):
    id = serializers.CharField(read_only = True)
    mail_id= serializers.IntegerField(read_only=True)
    bot_id =  serializers.IntegerField(read_only=True)
    saved_date =  serializers.DateTimeField(read_only=True)
    imap_uid = serializers.CharField()
    message_id = serializers.CharField(required=False, allow_null=True)
    thread_id = serializers.CharField(required=False, allow_null=True)
    from_email = serializers.EmailField(required=False, allow_null=True)
    from_name = serializers.CharField(required=False, allow_null=True)
    sender_domain = serializers.CharField(required=False, allow_null=True)
    to_email = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        allow_null=True
    )
    cc_email = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        allow_null=True
    )
    bcc_email = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        allow_null=True
    )
    subject = serializers.CharField(required=False, allow_null=True)
    body_text = serializers.CharField(required=False, allow_null=True)
    body_html = serializers.CharField(required=False, allow_null=True)
    has_body_html = serializers.BooleanField(default=False)
    date = serializers.DateTimeField(required=False, allow_null=True)
    received_date = serializers.DateTimeField(required=False, allow_null=True)
    synced_at = serializers.DateTimeField(required=False, allow_null=True)
    has_attachment = serializers.BooleanField(default=False)
    attachments = EmailAttachmentSerializer(many=True, required=False, default=[])
    labels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=[]
    )
    folder = serializers.CharField(default="INBOX")
    is_unread = serializers.BooleanField(default=True)
    priority = serializers.ChoiceField(
        choices=[(tag.value, tag.name) for tag in EmailPriority],
        default=EmailPriority.NORMAL.value
    )
    status = serializers.ChoiceField(
        choices=[(tag.value, tag.name) for tag in EmailStatus],
        default=EmailStatus.UNREAD.value
    )
    size = serializers.IntegerField(required=False, allow_null=True)
    headers = serializers.DictField(
        child=serializers.CharField(),
        required=False,
        default=dict
    )
    processed = serializers.BooleanField(default=False)
    applied_by_rules = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=[]
    )
    last_rule_applied_at = serializers.DateTimeField(required=False, allow_null=True)
    from_address = EmailAddressSerializer(required=False, allow_null=True)
    to_addresses = EmailAddressSerializer(many=True, required=False, allow_null=True)

    def create(self, validated_data):
        # Logique de création si nécessaire (ex: sauvegarde en base de données)
        pass

    def update(self, instance, validated_data):
        # Logique de mise à jour si nécessaire
        pass


class EmailListSerializer(serializers.Serializer):
    mail_id =  serializers.IntegerField()
    subject = serializers.CharField()
    from_name = serializers.CharField()
    from_email = serializers.EmailField()
    received_date = serializers.DateTimeField()
    status  =  serializers.CharField()
    is_unread = serializers.BooleanField()
    has_attachment =  serializers.BooleanField()
    priority =     priority = serializers.CharField()