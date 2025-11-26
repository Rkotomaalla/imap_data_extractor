from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class MongoDBConnection:
    """Singleton pour gérer la connexion MongoDB"""
    _instance = None
    _client = None
    _db = None
    
    def  __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDBConnection, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            self.connect()
    
    def connect(self):
        """Établir la connexion à MongoDB"""
        try:
            mongo_settings = settings.MONGODB_SETTINGS
            # Construction de l'URI MongoDB
            if mongo_settings.get('username') and mongo_settings.get('password'):
                uri = f"mongodb://{mongo_settings['username']}:{mongo_settings['password']}@{mongo_settings['host']}:{mongo_settings['port']}/"
            else:
                uri = f"mongodb://{mongo_settings['host']}:{mongo_settings['port']}/"
            
            self._client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000
            )
            
            # Test de connexion
            self._client.admin.command('ping')
            self._db = self._client[mongo_settings['db_name']]
            
            logger.info(f"✅ Connexion MongoDB réussie à {mongo_settings['db_name']}")
        except ConnectionFailure as e:
            logger.error(f"❌ Échec de connexion MongoDB: {e}")
            raise
        
        except Exception as e:
            logger.error(f"❌ Erreur lors de la connexion MongoDB: {e}")
            raise
        
    def get_database(self):
        """Retourner la base de données"""
        if self._db is None:
            self.connect()
        return self._db
    
    def get_collection(self, collection_name):
        """Retourner une collection spécifique"""
        db = self.get_database()
        return db[collection_name]
    
    
    def close(self):
        """Fermer la connexion"""
        if self._client:
            self._client.close()
            logger.info("🔒 Connexion MongoDB fermée")
            
# Instance globale
mongodb = MongoDBConnection()