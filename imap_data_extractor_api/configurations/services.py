import os
from pymongo import MongoClient
from django.conf import settings

class MongoDBService:
    def __init__(self):
        # connexion amin ny base de config (fallback URI)
        config_uri= settings.MONGO_CONFIG_URI
        self.config_client = MongoClient(config_uri)
        self.config_db = self.config_client['config_db']
        self.config_collection = self.config_db['mongo_config']
        
        # Récupération de la configuration dynamique
        self.config = self.config_collection.find_one({"name": "default"})
        if not self.config:
            raise ValueError("Configuration MongDb non trouvée")
        
        # Connextion a la vraie base de donnes
        
        self._connect_real_db()

    def _connect_real_db(self):                 
        cfg = self.config
        self.client = MongoClient(
            host=cfg['host'],
            port=cfg['port'],
            username=cfg.get('username'),
            password=cfg.get('password')
        )
        self.db = self.client[cfg['db_name']]
        
    def get_collection(self,name):
         """Récupère dynamiquement une collection de la base réelle."""
         return self.db.get_collection(name)
     
    def update_config(self, config_data):
        """Met à jour la configuration et reconnecte automatiquement."""
        self.config_collection.update_one(
            {"name": "default"},
            {"$set": config_data},
            upsert=True
        )
        # Recharge la config et reconnecte la base réelle
        self.config = self.config_collection.find_one({"name": "default"})
        self._connect_real_db()


# genelral
mongo_service = MongoDBService()
