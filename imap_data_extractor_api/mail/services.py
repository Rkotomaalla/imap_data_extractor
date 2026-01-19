from imap_data_extractor_api.utils  import get_next_sequence_value, serialize_mongo_doc
from configurations.services import mongo_service
from rest_framework.response import Response
from rest_framework import status


class MailService():
    def __init__(self):
        self.collection = mongo_service.get_collection('filtered_emails')
        
    def get_mail_id(self,mail_id):
        ESSENTIAL_FIELDS = {
                "_id": 0,
                "body_html" : 0
            }
        # Recherche dans MongoDB par gmail_message_id
        email = self.collection.find_one({"gmail_message_id": mail_id}, ESSENTIAL_FIELDS)

        if not email:
            return Response(
                {"detail": f"Aucun email trouvé avec id {pk}"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Sérialisation
        attachments = []
        email_data = serialize_mongo_doc(email)
        
        if email_data["has_attachment"]:
            attachment_collections = mongo_service.get_collection("attachment_email")
            attachments_doc = attachment_collections.find(
                {"gmail_message_id" : mail_id},
                {"_id" : 0}
            )
            attachments = [serialize_mongo_doc(a) for a in attachments_doc]
            
        return {
                "email" : email_data,
                "attachments" :  attachments   
        } 
        
mail_service = MailService()