from typing import Callable
from datetime import datetime,timezone
import logging
from email.utils import parsedate_to_datetime
from bot_filter.tasks import filter_task
import os
logger = logging.getLogger(__name__)


class BotExtractTask():
    
    def megabytes_to_kilobytes(self,mb_value: float, decimals: int = 2) -> float:
        """
        Convertit des mégaoctets (Mo) en kilooctets (Ko)
        """
        if not mb_value:
            return 0.0
        return round(mb_value * 1024, decimals)

    def bytes_to_kilobytes(self,bytes_value: int, decimals: int = 2) -> float:
        """
        Convertit un nombre d'octets en kilooctets (Ko).
        1 Ko = 1024 octets
        """
        if not bytes_value:
            return 0.0
        return round(bytes_value / 1024, decimals)
    def _parse_date(self,value):
        if isinstance(value, datetime):
            logger.info("date_time ilay izy ")
            return value

        if isinstance(value, str):
            # Tentative RFC email
            try:
                logger.info("Tentative parse to datetime")                
                dt = parsedate_to_datetime(value)
                if dt:
                    return dt
            except Exception:
                pass

            # Tentative ISO (YYYY-MM-DD)
            try:
                logger.info("Tentative iso")                
                return datetime.fromisoformat(value)
            except Exception:
                return None

        return None

    def _get_extension(self,filename: str | None) -> str:
        if not filename or '.' not in filename:
            return ""
        return filename.rsplit('.', 1)[-1].lower().strip()
    
    def _get_normalized_filenames(self, attachments: list | None = None) -> list[str]:
        return [
            os.path.splitext(att["filename"])[0].lower().strip()
            for att in (attachments or [])
            if isinstance(att, dict)
            and isinstance(att.get("filename"), str)
        ]
    def _handle_sent_date(self,rule_value,message_value, operator_id : int | None = None, attachments: list | None = None) -> bool:
        logger.info("Tonga ato am handle Date")        
        sent_date =self. _parse_date(message_value["date"])
        MIN_DATE = datetime.min.replace(tzinfo=timezone.utc)
        MAX_DATE = datetime.max.replace(tzinfo=timezone.utc)

        date_min =self. _parse_date(rule_value["value"][0]) if rule_value["value"][0] else MIN_DATE
        date_max = self._parse_date(rule_value["value"][1]) if rule_value["value"][1] else MAX_DATE
        logger.info("Dates reçues | min=%s | value=%s | max=%s",date_min, sent_date, date_max)
        if not sent_date or not date_min or not date_max:
            return False

        # Normalisation timezone
        # Normalisation timezone (simplifiée et plus robuste)
        sent_date = sent_date.astimezone(timezone.utc) if sent_date.tzinfo else sent_date.replace(tzinfo=timezone.utc)
        date_min  = date_min.astimezone(timezone.utc)  if date_min.tzinfo  else date_min.replace(tzinfo=timezone.utc)
        date_max  = date_max.astimezone(timezone.utc)  if date_max.tzinfo  else date_max.replace(tzinfo=timezone.utc)
            
        logger.info(f"Resultat de l inequation {date_min <= sent_date <= date_max}")
        return date_min <= sent_date <= date_max
    
        
    def _handle_has_attachment(self,rule_value, message_value,  operator_id : int | None = None, attachments: list | None = None)-> bool:
        count_att = len(attachments or [])
        logger.info(f"Nombre des attachments {count_att}")
        has_attachment_message =  True if count_att > 0  else False
        logger.info("Tonga ato am handle_has_attachment")
        message_value["has_attachment"] = has_attachment_message
        has_attachment_rule =rule_value['value']
        logger.info(f" valeur des attachments | attachment_rule : {has_attachment_rule} | attachment_mail : {has_attachment_message}")
        return has_attachment_rule == has_attachment_message
        
        
    def _handle_from(self,rule_value,message_value , operator_id : int | None = None, attachments: list | None = None)-> bool:
        logger.info("Tonga ato am handle from")
        
        from_rule_value = str(rule_value["value"])
        from_message_value = str(message_value["from_email"])
        
        logger.info(f" valeur des sender | sender_rule : {from_rule_value} | from_message_value : {from_message_value}")
        
        return from_rule_value == from_message_value 

    # 4:  {"filter_values" : value["value"], "email_value" : message["subject"],"operator_id" :operator},
    def _handle_subject(self, rule_value, message_value ,  operator_id : int | None = None, attachments: list | None = None )-> bool:
        logger.info("Tonga ato am handle subject")        
        subject_rule = rule_value["value"]
        subject_message =  message_value["subject"]
        kwarg = filter_task.operator_arg_handler(subject_rule,subject_message,  operator_id)
        result = filter_task.handle(operator_id, **kwarg)
        return result
                
    
    # 5 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" :operator},
    def _handle_attachments_count(self,rule_value, message_value: dict |  None=None ,operator_id : int | None = None, attachments: list | None = None)-> bool:
        count_att = len(attachments or [])
        count_rule = rule_value["value"]
        kwarg =  filter_task.operator_arg_handler(count_rule,count_att,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
            # 6 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" : operator},
        
    def _handle_total_attachments_size(self,rule_value,  message_value: dict |  None=None ,operator_id : int | None = None, attachments: list | None = None)-> bool:
        logger.info("Tonga atop amin'ny attachment_size")
        total_size =sum(att.get("size", 0) for att in attachments)
        total_size  = self. bytes_to_kilobytes(total_size,2)
        logger.info(f"total_size => {total_size}")
        
        size_rule =  rule_value["value"]
        size_rule  = self.megabytes_to_kilobytes(float(size_rule), 2)
        logger.info(f"size_rule=> {size_rule}")
        
        kwarg =  filter_task.operator_arg_handler(size_rule,total_size,operator_id)
        result =  filter_task.handle(operator_id , **kwarg) 
        return result
    
    def _handle_attachment_file_type(self,rule_value, message_value: dict |  None=None ,operator_id : int | None = None, attachments: list | None = None)-> bool:
        extensions = [self._get_extension(att.get("filename", "")) for att in (attachments or [])]
        extensions = [e for e in extensions if e]  # enlève les vides
        rule_type = rule_value["value"] 
        kwarg =  filter_task.operator_arg_handler(rule_type,extensions,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
            # 8 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" :operator}
    
    def _handle_attachment_file_name(self,rule_value, message_value: dict |  None=None ,operator_id : int | None = None, attachments: list | None = None)-> bool:
        filenames = self._get_normalized_filenames(attachments)
        name_rule = rule_value["value"]
        kwarg =  filter_task.operator_arg_handler(name_rule,filenames,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
            
    def  arg_handler(self,message_value,rule_value, field_id: int, operator_id: int | None = None,attachments: list | None = None)-> bool:
        operator = int(operator_id) if operator_id is not None else None
        logger.info(f"field_id =  {field_id}")
        mapping = {
            1 : self._handle_has_attachment,
            2 :  self._handle_sent_date,
            3: self._handle_from,
            4 : self._handle_subject,
            5 : self._handle_attachments_count,
            6 : self._handle_total_attachments_size,
            7 : self._handle_attachment_file_type,
            8 : self._handle_attachment_file_name
        }
        handler = mapping.get(field_id)
        if handler is None:
            logger.warning(f"Aucun handler pour field_id={field_id}")
            return False

        return handler(rule_value, message_value,operator_id,attachments)
        
    def handle(self,field_id,*args, **kwargs):
        func = self._handlers.get(field_id)
        if func is None:
            logger.warning("No handler for field_id=%d", field_id)
            return None
        try:
             return func(*args, **kwargs) 
        except Exception as e :
            logger.exception("Handler failed for field_id=%d: %s", field_id, e)
            raise

    
bot_task = BotExtractTask()     