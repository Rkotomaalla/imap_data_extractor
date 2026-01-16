from django.apps import AppConfig
from .services import mongo_service

class ConfigurationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'configurations'
    
    def ready(self):
        #initialise tous les indexs
        mongo_service.init_indexes()