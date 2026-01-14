from typing import Callable
from datetime import datetime
import logging
from email.utils import parsedate_to_datetime
logger = logging.getLogger(__name__)

class FilterTasks():
    def __init__(self):
        self._operators_handlers = {
            1: self._handle_contains_all,           # many: true
            2: self._handle_contains_any,           # many: true
            3: self._handle_equal,                  # many: false
            4: self._handle_between,                # many: true (range)
            5: self._handle_inferior,               # many: false
            6: self._handle_superior,               # many: false
            7: self._handle_attachment_name_contains,  # many: false
            8: self._handle_attachment_type_equal,     # many: false
            9: self._handle_attachment_types_are,      # many: true
        }
    
    # ────────────────────────────────────────────────
    # Opérateurs texte / général
    # ────────────────────────────────────────────────
    def  _handle_contains_all(self, filter_values : list[str], text : str) -> bool:
        if not filter_values:
            return True
        words = set(text.lower().split())
        return all(v.lower() in words for v in filter_values)
    

    def _handle_contains_any(self, filter_values: list[str], text: str) -> bool:
        if not filter_values:
            return False
        words = set(text.lower().split())
        return any(v.lower() in words for v in filter_values)

    
    def _handle_equal(self, filter_value: str | int | float, value: str | int | float) -> bool:
        return str(filter_value).lower() == str(value).lower()   # on normalise un peu

    # ────────────────────────────────────────────────
    # Opérateurs numériques
    # ────────────────────────────────────────────────
    def _handle_between(self, range_values: list, number: int | float) -> bool:
        if len(range_values) != 2:
            return False
        min_val = range_values[0] if range_values[0] is not None else float('-inf')
        max_val = range_values[1] if range_values[1] is not None else float('inf')
        return min_val <= number <= max_val
    
    
    def _handle_inferior(self, limit, number: int | float) -> bool:
        return  number < limit
    
    
    def _handle_superior(self, limit, number: int | float) -> bool:
        return number > limit
    
    # ────────────────────────────────────────────────
    # Opérateurs pièces jointes
    # ────────────────────────────────────────────────
    def _handle_attachment_name_contains(self, substring: str, filenames: list[str]) -> bool:
        if not filenames:
            return False
        substring = substring.lower().strip()
        return any(substring in name for name in filenames)
    
    def _handle_attachment_type_equal(self, expected_type: str, extensions: list[str]) -> bool: 
        if not extensions:
            return False
        expected = expected_type.lower().lstrip('.').strip()
        return all(ext == expected for ext in extensions)
    
    def _handle_attachment_types_are(self, allowed_types: list[str], extensions: list[str]) -> bool:
        if not extensions:
            return False
        allowed = {t.lower().lstrip('.').strip() for t in allowed_types}
        return set(extensions) <= allowed

    def  operator_arg_handler(self, filter_value, target_value, operator_id: int | None = None):
        mapping = {
            # many: true
            1: {"filter_values": filter_value, "text": target_value},
            2: {"filter_values": filter_value, "text": target_value},
            4: {"range_values": filter_value, "number": target_value},
            9: {"allowed_types": filter_value, "extensions": target_value},

            # many: false
            3: {"filter_value": filter_value, "value": target_value},
            5: {"limit": filter_value, "number": target_value},
            6: {"limit": filter_value, "number": target_value},
            7: {"substring": filter_value, "filenames": target_value},
            8: {"expected_type": filter_value, "extensions": target_value},
        }
        return mapping.get(operator_id, {})
        
        
        
    def handle(self,operator_id, *args , **kwargs):
        func  =  self._operators_handlers.get(operator_id)
        if func is None:
            logger.warning("No handler for operator_id=%d", operator_id)
            return None
        try:
             return func(*args, **kwargs) 
        except Exception as e :
            logger.exception("Handler failed for operator=%d: %s", operator_id, e)
            raise
        
filter_task =  FilterTasks()