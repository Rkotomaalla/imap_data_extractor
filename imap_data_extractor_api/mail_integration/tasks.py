from celery import shared_task
from googleapiclient.errors import HttpError
from .services import gmail_service
from configurations.services import mongo_service
from datetime import datetime
from bots.service import bot_service
from bots.tasks import bot_task
from bots.serializer import BotSerializer
from email.utils import parseaddr
from imap_data_extractor_api.utils import serialize_mongo_doc, get_next_sequence_value
import logging
import base64
from notifications.services import ConsoleNotification,mail_notification

logger = logging.getLogger(__name__)

    
def get_message_att(user_id, gmail_message_id):
    service = gmail_service.get_gmail_service(user_id)
    message = service.users().messages().get(
        userId="me",
        id=gmail_message_id,
        format="full"
    ).execute()
    payload = message["payload"]
    attachments = gmail_service.extract_attachments(payload)
    return {
        "message": message,
        "attachments": attachments,
        "service": service
    }


@shared_task
def apply_bot_filter(user_id, gmail_message_id, bot, indexed_map):
    messages_collection = mongo_service.get_collection("raw_emails")
    field_collection = mongo_service.get_collection("fields")
    
    ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),f"Traitement du nouveau mail {gmail_message_id} par le bot",0)        
    
    # recuperation du message 
    mongo_message = messages_collection.find_one({
        "gmail_message_id": gmail_message_id
    })
    if not mongo_message:
        error_message = f"Message introuvable : {gmail_message_id}" 
        logger.error(error_message)
        ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),error_message,2)        
        return False

    filter_data = bot.get("filter", {})
    rq_all = filter_data.get("required_all", False)
    rules = filter_data.get("rules", [])
    
    if not rules:
        warning_message = "règle définie pour ce bot"
        logger.warning(warning_message)
        ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),warning_message,3)        
        return False
    
    ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),f"Verificationd des regles du bot mail : {gmail_message_id}" ,3)        
        
    priorities_data = gmail_service.sort_rules_by_indexed_priority(rules, indexed_map)
    bot_rules = priorities_data.get("result", [])
    priority_limit = priorities_data.get("true", 0)
    logger.info(f"Rules triées : {bot_rules}")
    
    gmail_data = None 
    is_mail_valid = False
    attachments = []
    
    message = "application des règles"
    ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),f"Application des regles sur le nouveau mail {gmail_message_id} par le bot",0)        
    for i, bot_rule in enumerate(bot_rules, start=1):
        field_id = bot_rule.get("field_id")

        if field_id is None:
            message = "field_id manquant dans la règle"
            logger.error(message)
            ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),f"field_id manquant dans la règle : mail {gmail_message_id}",2)        
            continue

        field_id = int(field_id)
        
        field_doc = field_collection.find_one({"field_id": int(field_id)})
        
        if not field_doc:
            message = f"Field introuvable : {field_id}"
            logger.error(message)
            ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),message,2)        
            continue
            
        message = f"Traitement du bot par un règle"
        logger.info(f"Traitement règle | field_id={field_id} | bot_rule={bot_rule}")
        ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),f"Filtrage du mail par les regles mail {gmail_message_id}",0)        

        is_rule_valid = False
        need_attachment = field_doc.get("need_attachment", False)
        
        value = bot_rule.get("value")
        if value is None:
            message = "value manquante dans la règle"
            logger.error(message)    
            ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),message,2)        
            continue
            
        # chargement si necessaire des pieces jointes
        if need_attachment:
            if gmail_data is None:
                message = "extractions des pieces jointes"
                ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),message,0)        
                gmail_data = get_message_att(user_id, gmail_message_id) or {}
                logger.info(f"Données pièces jointes : {gmail_data.get('attachments', [])}")
                attachments = gmail_data.get("attachments", [])
                
        # securite de l operator_id
        operator_id = bot_rule.get("operator_id")
        operator_id = int(operator_id) if operator_id is not None else None
        
        if i <= priority_limit:
            if need_attachment:
                is_rule_valid = bot_task.arg_handler(mongo_message, value, field_id, None, attachments)            
            else:
                is_rule_valid = bot_task.arg_handler(mongo_message, value, field_id)            
        else:
            if need_attachment:
                is_rule_valid = bot_task.arg_handler(mongo_message, value, field_id, operator_id, attachments)
            else:
                is_rule_valid = bot_task.arg_handler(mongo_message, value, field_id, operator_id)
        
        if is_rule_valid:
            if rq_all:
                is_mail_valid = True
                continue
            else:
                message = f"Règle validée enregistrement du mail {gmail_message_id} en cours"
                ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),message,1)        
                logger.info("Règle validée, required_all=False → arrêt")
                is_mail_valid = True
                break
        else:
            if rq_all:
                return False
            else:
                continue
                
    # fonction enregistrement du message et enregistrement des pieces jointes        
    if not is_mail_valid:
        return False
    
    if gmail_data is None:
        gmail_data = get_message_att(user_id, gmail_message_id) or {}
        attachments = gmail_data.get("attachments", [])
    
    full_message = gmail_data.get("message")
    service = gmail_data.get("service")
    
    if not service:
        logger.error("Service non recuperé dans le foltre du bot")
        return False            
    
    if not full_message:
        logger.error("Message complete Gmail introuvable après récupération")
        return False            
    
    bot_id = bot.get("bot_id", 0)
    has_attachments = bool(attachments)
    mail_extracted = gmail_service.extract_mail_data(user_id, full_message, bot_id, has_attachments) 
    
    result = gmail_service.save_email_and_attachments(service, user_id, gmail_message_id, mail_extracted, attachments)
    
    if not result:
        message = f"erreur lors de l enregistrement du mail {gmail_message_id}"
        ConsoleNotification.send_console_notif(user_id,bot.get("bot_id"),message,2)        
        return False
    return True    


# ✅ AJOUT DU @shared_task
@shared_task
def dispatch_mail_to_bots(user_id, gmail_message_id):
    bot_collection = mongo_service.get_collection("bot")
    fields_collection = mongo_service.get_collection("fields")
    
    bots = list(bot_collection.find({
        "assigned_user_id": user_id,
        "status": 1
    }))
    
    print(
        f"\nReto ny bots+++++++++++++++++++++++++++++++++++\n"
        f"{bots}\n"
        f"+++++++++++++++++++++++++++++++++++++++++++++++++++"
    )
    
    fields_dict = fields_collection.find()
    indexed_map = {int(f["field_id"]): f["is_indexed"] for f in fields_dict}
    
    print(f"RETO NY INDEX\n{indexed_map}\n========================================================")
    matched_id_bot = []
    for bot in bots:
        print(f"Mandalo eto am boucle========================================================")            
        bot_result = serialize_mongo_doc(bot)
        bot_serializer = BotSerializer(bot_result)
        
        print(f"boucle\n{bot_serializer.data}\n========================================================")
        
        # envoi de la notification de reception des mails
        notification_message = f"Un nouveaux mail {gmail_message_id} en cours de traitement"
        ConsoleNotification.send_console_notif(user_id,bot_serializer.data.get("bot_id"),notification_message,0)

        res =  apply_bot_filter.delay(
            user_id=user_id,
            gmail_message_id=gmail_message_id,
            bot=bot_serializer.data,
            indexed_map=indexed_map
        )
    #     result = res.get()
    #     if result == True:
    #         matched_id_bot.append(bot_serializer.data.get("bot_id"))
    
    # if matched_id_bot.count > 0:
    #     notification_message = f"Un nouveaux mail {gmail_message_id} est enregistrer"
    #     mail_notification.send_new_mail_notif(user_id,matched_id_bot,gmail_message_id,notification_message,4)            


# ✅ CORRECTION COMPLÈTE
@shared_task(bind=True, max_retries=2)
def process_gmail_message(self, user_id, message_id):
    """Récupère le mail Gmail et l'envoie aux bots"""
    gmail_collection = mongo_service.get_collection("gmail_token")
    messages_collection = mongo_service.get_collection("raw_emails")
    
    user_doc = gmail_collection.find_one({"user_id": user_id})
    
    if not user_doc:
        logger.warning(f"Utilisateur {user_id} introuvable")
        return

    try:
        # Récupérer le service Gmail avec gestion du refresh token
        service = gmail_service.get_gmail_service(user_id)

        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="metadata",   
            metadataHeaders=["From", "To", "Subject", "Date"]
        ).execute()
        
    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(f"⚠️ Message {message_id} introuvable (404) - probablement supprimé")
            return  # ✅ Ne pas crasher
        elif e.resp.status in [429, 500, 503]:
            logger.warning(f"Erreur temporaire {e.resp.status}, retry dans 60s...")
            raise self.retry(exc=e, countdown=60)
        else:
            logger.error(f"Erreur Gmail API: {e}")
            raise
    
    # Extraire les infos importantes
    headers = {h["name"]: h["value"] for h in message["payload"]["headers"]}
    logger.info(f"=========================>Message reçu ID: {message.get('id')}")
    logger.info(f"=========================>Subject: {headers.get('Subject')}")

    from_name, from_email = parseaddr(headers.get("From"))
    gmail_message_id = message.get("id")
    
    # ✅ VÉRIFIER SI LE MESSAGE EXISTE DÉJÀ
    existing = messages_collection.find_one({"gmail_message_id": gmail_message_id})
    
    if existing:
        logger.info(f"⚠️ Message {gmail_message_id} déjà traité - Skip")
        return
    
    # ✅ Message nouveau
    raw_emails_id = get_next_sequence_value("raw_emails")
    
    mail_data = {
        "raw_emails_id": raw_emails_id,
        "user_id": user_id,
        "gmail_message_id": gmail_message_id,
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
    
    logger.info(f"\n📧 Mail data:\n{mail_data}\n")
    
    try:
        # ✅ INSERTION SIMPLE
        messages_collection.insert_one(mail_data)
        logger.info(f"✅ Message {gmail_message_id} enregistré avec raw_emails_id={raw_emails_id}")
        
    except Exception as e:
        # Race condition possible
        if "duplicate key error" in str(e).lower():
            logger.warning(f"⚠️ Message {gmail_message_id} déjà inséré par un autre worker - Skip")
            return
        logger.error(f"❌ Erreur MongoDB: {e}")
        raise

    # ✅ APPEL ASYNCHRONE
    dispatch_mail_to_bots.delay(user_id, gmail_message_id)