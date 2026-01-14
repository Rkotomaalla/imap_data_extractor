from celery import shared_task
from  .services  import gmail_service
from configurations.services import mongo_service
from datetime import datetime
from bots.service import bot_service
from bots.tasks import bot_task
from bots.serializer import BotSerializer
from imap_data_extractor_api.utils import serialize_mongo_doc, parse_object_id
import logging
logger = logging.getLogger(__name__)

def get_attachment(user_id,gmail_message_id):
    service = gmail_service.get_gmail_service(user_id)
    message = service.users().messages().get(
        userId="me",
        id=gmail_message_id,
        format="full"
    ).execute()
    payload = message["payload"]
    attachments=gmail_service.extract_attachments(payload)
    return {
        "service" :  service,
        "payload" : payload,
        "attachments" : attachments
    }
    
    
    
@shared_task
def apply_bot_filter(user_id, gmail_message_id,bot,indexed_map):
    messages_collection = mongo_service.get_collection("gmail_message")
    field_collection = mongo_service.get_collection("fields")
    message = messages_collection.find_one({
        "gmail_message_id": gmail_message_id
    })
    
    logger.info(f"Bot recu {bot}")
    
    gmail_data  = None 
    rq_all = bot.get('filter').get("required_all")
    rules =  bot.get('filter').get("rules")
    
    priorities_data = gmail_service.sort_rules_by_indexed_priority(rules, indexed_map) 
    bot_rules= priorities_data["result"]
    
    logger.info(f"Rules =>  {bot_rules}")
    
    for i, bot_rule in enumerate(bot_rules, start=1):
        field_id = int(bot_rule["field_id"])
        field_doc = field_collection.find_one({
            "field_id" : int(field_id)        
        })
        
        logger.info(f"id du Field {field_id}")
        logger.info(f"le valeur utiles => messsage => {message} | bot_rule => {bot_rule}")
        
        if i <= priorities_data["true"]:
            kwarg = bot_task.arg_handler(message,bot_rule["value"],field_id)            
        else:
            if  field_doc["need_attachment"]:

                logger.info("Dans ")
                if  gmail_data  is None:
                    gmail_data = get_attachment(user_id,gmail_message_id)
                kwarg = bot_task.arg_handler(message, bot_rule["value"],field_id,int(bot_rule["operator_id"]),gmail_data["attachments"])
            else:
                kwarg = bot_task.arg_handler(message, bot_rule["value"],field_id,int(bot_rule["operator_id"]))
        logger.info(f"kwarg final {kwarg}")

        is_valid = bot_task.handle(field_id, **kwarg)

        logger.info(f"Validation email du champ  {field_id} est _{is_valid}")
            
            
            

@shared_task
def dispatch_mail_to_bots(user_id, gmail_message_id):
    bot_collection =  mongo_service.get_collection("bot")
    fields_collection = mongo_service.get_collection("fields")
    bots = list(bot_collection.find({
        "assigned_user_id": user_id
    }))
    print(
        f"\nReto ny bots+++++++++++++++++++++++++++++++++++\n"
        f"{bots}\n"
        f"+++++++++++++++++++++++++++++++++++++++++++++++++++"
    )
    fields_dict  = fields_collection.find()
    indexed_map = {int(f["field_id"]): f["is_indexed"] for f in fields_dict}
    print(f"RETO NY INDEX\n{indexed_map}\n========================================================")
    for bot in bots:
        print(f"Mandalo eto am boucle========================================================")    
        bot_result = serialize_mongo_doc(bot)
        bot_result = BotSerializer(bot_result)
        print(f"boucle\n{bot_result.data}\n========================================================")    
        apply_bot_filter.delay(
            user_id = user_id,
            gmail_message_id = gmail_message_id,
            bot = bot_result.data,
            indexed_map  = indexed_map
        )
        
        
        
        
@shared_task
def process_gmail_message(user_id, message_id):
    """Récupère le mail Gmail et l’envoie aux bots"""
    gmail_collection=mongo_service.get_collection("gmail_token")
    messages_collection = mongo_service.get_collection("gmail_message")  # nouvelle collection
    """Récupère le mail Gmail et l’envoie aux bots"""
    user_doc = gmail_collection.find_one({"user_id": user_id})
    if not user_doc:
        return

    # Récupérer le service Gmail avec gestion du refresh token
    service = gmail_service.get_gmail_service(user_id)

    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="metadata",   
        metadataHeaders=["From", "To", "Subject", "Date"]
    ).execute()
    # Extraire les infos importantes
    headers = {h["name"]: h["value"] for h in message["payload"]["headers"]}
    
    has_attachment = any(
        part.get("filename")
        for part in message["payload"].get("parts", [])
    )
    
    mail_data = {
        "user_id": user_id,
        "gmail_message_id": message.get("id"),
        "thread_id": message.get("threadId"),
        "from": headers.get("From"),
        "to": headers.get("To"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
        "snippet": message.get("snippet"),
        "label_ids": message.get("labelIds", []),
        "received_at": datetime.utcnow(),
        "has_attachment" : has_attachment
    }   
    print(f"\nito ilay mail====================\n{mail_data}\n=====================\n")
    messages_collection.update_one(
        {"gmail_message_id": message["id"]},
        {"$set": mail_data},
        upsert=True
    )

    dispatch_mail_to_bots.delay(user_id,message["id"])
    
    # Stocker dans MongoDB
    # messages_collection.update_one(
    #     {"gmail_message_id": message.get("id")},
    #     {"$set": mail_data},
    #     upsert=True
    # )

    
        
