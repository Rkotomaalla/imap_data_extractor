from typing import Callable
from datetime import datetime,timezone
import logging
from email.utils import parsedate_to_datetime
from bot_filter.tasks import filter_task
logger = logging.getLogger(__name__)


class BotExtractTask():
    
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
    
    def _get_normalized_filenames(attachments: list[str] | None) -> list[str]:
        if not attachments:
            return []
        return [name.lower().strip() for name in attachments if name and isinstance(name, str)]
    
    
    def _handle_sent_date(self, sent_date : str |None | datetime, date_min : str |None | datetime , date_max: str |None | datetime):
        logger.info("Tonga ato am handle Date")
        sent_date =self. _parse_date(sent_date)
        date_min =self. _parse_date(date_min) if date_min else datetime(1700, 1, 1)
        date_max = self._parse_date(date_max) if date_max else datetime(3000, 1, 1)
        logger.info("Dates reçues | min=%s | value=%s | max=%s",date_min, sent_date, date_max)
        if not sent_date or not date_min or not date_max:
            return False

        # Normalisation timezone
        if sent_date.tzinfo:
            sent_date = sent_date.astimezone(timezone.utc)
        else:
            sent_date = sent_date.replace(tzinfo=timezone.utc)

        if date_min.tzinfo is None:
            date_min = date_min.replace(tzinfo=timezone.utc)
        if date_max.tzinfo is None:
            date_max = date_max.replace(tzinfo=timezone.utc)
        
        logger.info(f"Resultat de l inequation {date_min <= sent_date <= date_max}")
        return date_min <= sent_date <= date_max
        
    
    
    def _handle_has_attachment(self,has_attachment_rule : bool | None, has_attachment_mail : bool | None):
        logger.info("Tonga ato am handle_has_attachment")
        logger.info(f" valeur des attachments | attachment_rule : {has_attachment_rule} | attachment_mail : {has_attachment_mail}")
        return has_attachment_rule == has_attachment_mail
    
    
    def _handle_from(self, from_value , from_rule):
        return from_value == from_rule
        
        
    def  _handle_subject(self,filter_values, email_value, operator_id):
        kwarg = filter_task.operator_arg_handler(filter_values, email_value,operator_id)
        result = filter_task.handle(operator_id, **kwarg)
        return result
        
    def _handle_attachments_count(self,filter_value,attachments: list | None, operator_id: int):
        count = len(attachments)
        kwarg =  filter_task.operator_arg_handler(filter_value, count,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
    
    def _handle_total_attachments_size(self,filter_value,attachments: list | None, operator_id: int):
        total_size = sum(att.get("size", 0) for att in attachments)
        kwarg =  filter_task.operator_arg_handler(filter_value,total_size,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
    
    def _handle_attachment_file_type(self,filter_value,attachments: list | None, operator_id: int):
        extensions = [self._get_extension(name) for name in (attachments or [])]
        extensions = [e for e in extensions if e]  # enlève les vides
        kwarg =  filter_task.operator_arg_handler(filter_value,extensions,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
    
    def _handle_attachment_file_name(self,filter_value,attachments: list | None, operator_id: int):
        filenames = self._get_normalized_filenames(attachments)
        kwarg =  filter_task.operator_arg_handler(filter_value,filenames,operator_id)
        result =  filter_task.handle(operator_id , **kwarg)
        return result
    
    def __init__(self):
        self._handlers: dict[int, Callable] = {
            1: self._handle_has_attachment,
            2: self._handle_sent_date,
            3: self._handle_from,
            4 : self._handle_subject,
            5 : self._handle_attachments_count,
            6 : self._handle_total_attachments_size,
            7 : self._handle_attachment_file_type,
            8 : self._handle_attachment_file_name
        }
        
        
        
    def  arg_handler(self,message,value, field_id: int, operator_id: int | None = None,attachments: list | None = None):
        operator = int(operator_id) if operator_id is not None else None
        logger.info(f"field_id =  {field_id}")
        mapping = {
            1 : {"has_attachment_rule": value['value'] , "has_attachment_mail" : message["has_attachment"] },
            2 : {"sent_date" : message["date"] , "date_min" : value["value"][0],"date_max" : value["value"][1]},
            3 : {"from_value": message["from"] , "from_rule" :  value["value"]},
            4:  {"filter_values" : value["value"], "email_value" : message["subject"],"operator_id" :operator},
            5 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" :operator},
            6 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" : operator},
            7 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" :operator},
            8 : {"filter_value" :  value["value"] , "attachments" :  attachments , "operator_id" :operator}
        }
        logger.info(f"donc mapping = {mapping.get(field_id)}")
        return mapping.get(field_id)
        
    
    
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