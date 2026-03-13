from celery import shared_task
from  .services  import gmail_service
from configurations.services import mongo_service
from datetime import datetime
from bots.service import bot_service
from bots.tasks import bot_task
from bots.serializer import BotSerializer
from email.utils import parseaddr
from imap_data_extractor_api.utils import serialize_mongo_doc, get_next_sequence_value
import logging
import base64
from notifications.services import notification

logger = logging.getLogger(__name__)

    
def get_message_att(user_id,gmail_message_id):
    service = gmail_service.get_gmail_service(user_id)
    message = service.users().messages().get(
        userId="me",
        id=gmail_message_id,
        format="full"
    ).execute()
    payload = message["payload"]
    attachments=gmail_service.extract_attachments(payload)
    return {
        "message" : message,
        "attachments" : attachments,
        "service" : service
    }

@shared_task
def apply_bot_filter(user_id, gmail_message_id,bot,indexed_map):
    messages_collection = mongo_service.get_collection("raw_emails")
    field_collection = mongo_service.get_collection("fields")
    
    # recuperation du message 
    mongo_message = messages_collection.find_one({
        "gmail_message_id": gmail_message_id
    })
    if not mongo_message:
        error_message = f"Message introuvable : {gmail_message_id}" 
        logger.error(error_message)
        notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,error_message,5)
        return False
    
    filter_data = bot.get("filter", {})
    rq_all = filter_data.get("required_all",False)
    rules =  filter_data.get("rules",[])
    
    if not rules:
        warning_message = "règle définie pour ce bot"
        logger.warning(warning_message)
        notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,warning_message,0)
        
        return False
        
    priorities_data = gmail_service.sort_rules_by_indexed_priority(
        rules, indexed_map
    )
     
    bot_rules = priorities_data.get("result", [])
    
    priority_limit = priorities_data.get("true", 0)
    logger.info(f"Rules triées : {bot_rules}")
    
    gmail_data  = None 
    
    is_mail_valid = False
    
    attachments = []
    
    message = "application des règles"
    for i, bot_rule in enumerate(bot_rules, start=1):
       
        field_id = bot_rule.get("field_id")

        if field_id is None:
            message = "field_id manquant dans la règle"
            logger.error(message)
            notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,5)            
            continue

        field_id = int(field_id)
        
        field_doc = field_collection.find_one({
            "field_id" : int(field_id)        
        })
        
        if not field_doc:
            message = f"Field introuvable : {field_id}"
            logger.error(message)
            notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,5)            
            
            continue
        message =  f"Traitement du bot par un règle"
        logger.info(
            f"Traitement règle | field_id={field_id} | bot_rule={bot_rule}"
        )
        notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,2)            
        
        is_rule_valid = False
        need_attachment = field_doc.get("need_attachment", False)
        
        value = bot_rule.get("value")
        if value is None:
            message = "value manquante dans la règle"
            logger.error(message)
            notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,5)            
            
            continue
        #chargment si necessaire des pieces jointes
        if need_attachment:
            if gmail_data is None:
                message = "extractions des pieces jointes"
                notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,2)            
                
                gmail_data =  get_message_att(user_id,gmail_message_id) or {}
                logger.info(
                    f"Données pièces jointes : {gmail_data.get('attachments', [])}"
                )
                attachments = gmail_data.get("attachments", [])
        # sercurite de l operator_id
        operator_id = bot_rule.get("operator_id")
        operator_id = int(operator_id) if operator_id is not None else None
        
        
        if i <= priority_limit:
            if  need_attachment:
                is_rule_valid = bot_task.arg_handler(mongo_message,value,field_id,None,attachments)            
            else:
                is_rule_valid = bot_task.arg_handler(mongo_message,value,field_id)            
        else:
            if  need_attachment:
                is_rule_valid = bot_task.arg_handler(mongo_message,value,field_id,operator_id,attachments)
            else:
                is_rule_valid = bot_task.arg_handler(mongo_message, value, field_id,operator_id)
        
        if is_rule_valid :
            if rq_all:
                is_mail_valid = True
                continue
            else:
                message ="Règle validée enregistrement du mail en cours"
                notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,2)            
                logger.info("Règle validée, required_all=False → arrêt")
                is_mail_valid= True
                break
        else:
            if rq_all:
                return False
            else : 
                continue
                
    # fonction enregistrement du message et enregistrement des pieces jointes        
    if not is_mail_valid:
        return False
    
    if gmail_data is None:
        gmail_data =  get_message_att(user_id,gmail_message_id) or {}
        attachments = gmail_data.get("attachments", [])
    
    full_message = gmail_data.get("message")
    service = gmail_data.get("service")
    
    if not service :
        logger.error("Service non recuperé dans le foltre du bot")
        return False            
    
    if not full_message:
        logger.error("Message complete Gmail introuvable après récupération")
        return False            
    
    bot_id =  bot.get("bot_id", 0)
    has_attachments = bool(attachments)
    mail_extracted = gmail_service.extract_mail_data(user_id,full_message,bot_id,has_attachments) 
    
    result =  gmail_service.save_email_and_attachments(service,user_id,gmail_message_id,mail_extracted,attachments)
    
    if not result:
        message = "erreur lors de l enregistrement du mail"
        notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,5)            
        
        return False
    message = f"Mail enregistrer avec succes: id_mail : {gmail_message_id}"
    notification.notify_email_process(user_id, bot.get("bot_id"),gmail_message_id,message,4)            
    logger.info(f"Un mail est enregistter , id mail {gmail_message_id} par l'utilisateur {user_id}")
    return True    
        
            
            
def dispatch_mail_to_bots(user_id, gmail_message_id):
    bot_collection =  mongo_service.get_collection("bot")
    fields_collection = mongo_service.get_collection("fields")
    bots = list(bot_collection.find({
        "assigned_user_id": user_id,
        "status" : 1
    }))
    
    # Print debug du document 4
    print(
        f"\nReto ny bots+++++++++++++++++++++++++++++++++++\n"
        f"{bots}\n"
        f"+++++++++++++++++++++++++++++++++++++++++++++++++++"
    )
    
    fields_dict  = fields_collection.find()
    indexed_map = {int(f["field_id"]): f["is_indexed"] for f in fields_dict}
    
    # Print debug du document 4
    print(f"RETO NY INDEX\n{indexed_map}\n========================================================")

    for bot in bots:
        # Print debug du document 4
        print(f"Mandalo eto am boucle========================================================")            
        bot_result = serialize_mongo_doc(bot)
        bot_result = BotSerializer(bot_result)
        
        # Print debug du document 4
        print(f"boucle\n{bot_result.data}\n========================================================")
        
        # envoi de la notification de reception des mails
        notification_message = f"Un nouveaux mail {gmail_message_id} en cours de traitement"
        notification.notify_email_process(user_id, bot_result.data.get("bot_id"),gmail_message_id,notification_message,1)

        apply_bot_filter.delay (
            user_id = user_id,
            gmail_message_id = gmail_message_id,
            bot = bot_result.data,
            indexed_map  = indexed_map
        )
        
        
        
        
@shared_task
def process_gmail_message(user_id, message_id):
    """Récupère le mail Gmail et l'envoie aux bots"""
    gmail_collection=mongo_service.get_collection("gmail_token")
    messages_collection = mongo_service.get_collection("raw_emails")  # nouvelle collection
    """Récupère le mail Gmail et l'envoie aux bots"""
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
    logger.info(f"=========================>valeur de message reçu {message}")
    logger.info(f"=========================>valeur du payload reçu {message["payload"]}")

    from_name , from_email = parseaddr(headers.get("From")) 
    raw_emails_id =  get_next_sequence_value("raw_emails")    
    
    mail_data = {
        "user_id": user_id,
        "gmail_message_id": message.get("id"),
        "thread_id": message.get("threadId"),
        "from_name": from_name,
        "from_email": from_email,
        "to": headers.get("To"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
        "snippet": message.get("snippet"),
        "label_ids": message.get("labelIds", []),
        "received_at": datetime.utcnow()
    }
    
    # Logger du document 4
    logger.info(f"\nito ilay mail\n{mail_data}\n")
    
    messages_collection.update_one(
        {"raw_emails_id": raw_emails_id},
        {"$setOnInsert": mail_data},
        upsert=True
    )

    dispatch_mail_to_bots(user_id,mail_data["gmail_message_id"])