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
            pipeline = [
                {"$match": {"gmail_message_id": mail_id}},
                {"$group": {
                    "_id": "$storage_path",
                    "storage_path":       {"$first": "$storage_path"},
                    "filename":           {"$first": "$filename"},
                    "mime_type":          {"$first": "$mime_type"},
                    "size":               {"$first": "$size"},
                    "attachment_id":      {"$first": "$attachment_id"},
                    "attachment_email_id":{"$first": "$attachment_email_id"},
                    "gmail_message_id":   {"$first": "$gmail_message_id"},
                    "user_id":            {"$first": "$user_id"},
                    "created_at":         {"$first": "$created_at"},
                }},

                {"$project": {"_id": 0}}
            ]
            # attachments_doc = attachment_collections.find(
            #     {"gmail_message_id" : mail_id},
            #     {"_id" : 0}
            # )
            attachments_doc = attachment_collections.aggregate(pipeline)
            attachments = [serialize_mongo_doc(a) for a in attachments_doc]
            
        return {
                "email" : email_data,
                "attachments" :  attachments   
        } 
    
    
    
    
    def get_email_bots(self,pk=None):
        try:
            filtered_collection = mongo_service.get_collection ('filtered_emails')
            if not pk:
                raise Exception("L'identifiant de l'email est obligatoire")

            pipeline = [
                {"$match": {"gmail_message_id": pk}},
                {"$group": {
                    "_id": "$gmail_message_id",
                    "bot_ids": {"$addToSet": "$bot_id"}
                }},
                {"$project": {"_id": 0, "bot_ids": 1}}
            ]

            result = list(filtered_collection.aggregate(pipeline))

            return result[0].get("bot_ids", []) 

        except Exception as e:
            raise Exception("Erreur lors de la recuperationd des bots de l email {pk}:{e.message}")
mail_service = MailService()