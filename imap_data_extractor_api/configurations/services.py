import os
from pymongo import MongoClient , ASCENDING
from django.conf import settings
from rest_framework.exceptions import ValidationError
from pymongo.errors import ConnectionFailure, OperationFailure, ConfigurationError

import logging
logger = logging.getLogger(__name__)
class MongoDBService:
    def __init__(self):
        # connexion amin ny base de config (fallback URI)
        config_uri= settings.MONGO_CONFIG_URI
        self.config_client = MongoClient(config_uri)
        self.config_db = self.config_client['config_db']
        self.config_collection = self.config_db['mongo_config']
        self.version_collection = self.config_db['version_config']
        # Récupération de la configuration dynamique
        self.config = self.config_collection.find_one({"is_active": True})
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
     
    def init_indexes(self):
        try:
            # ===== Piece jointes =====
            self.db.attachment_email.create_index(
                [("attachment_id", ASCENDING)],
                unique=True,
                name="unique_attachment_id"
            )
            logger.info("Index unique 'attachment_id' créé pour filtered_emails")

            #============Bot
            self.db.bot.create_index(
                    [("bot_id", ASCENDING)],
                    unique=True,
                    name="unique_bot_id"
                )
            logger.info("Index unique 'bot_id' créé pour filtered_emails")

            #============bot_archive_id
            self.db.bot_archive.create_index(
                    [("bot_archive_id", ASCENDING)],
                    unique=True,
                    name="unique_bot_archive_id"
                )
            logger.info("Index unique 'bot_archive_id' créé pour filtered_emails")
            
            #===========field
            self.db.fields.create_index(
                    [("field_id", ASCENDING)],
                    unique=True,
                    name="unique_bot_archive_id"
                )
            logger.info("Index unique 'bot_archive_id' créé pour filtered_emails")

            #===========Filtered_email
            self.db.filtered_emails.create_index(
                    [("gmail_message_id", ASCENDING)],
                    unique=True,
                    name="unique_gmail_message_id"
                )
            logger.info("Index unique 'gmail_message_id' créé pour filtered_emails")

            #===========gmail_token
            self.db.gmail_token.create_index(
                    [("user_id", ASCENDING)],
                    unique=True,
                    name="unique_user_id_gmail_token"
                )
            logger.info("Index unique 'user_id' créé pour filtered_emails")

            #===========operators
            self.db.operators.create_index(
                    [("operator_id", ASCENDING)],
                    unique=True,
                    name="unique_operator_id"
                )
            logger.info("Index unique 'operator_id' créé pour filtered_emails")
            
            #================raw email 
            self.db.raw_emails.create_index(
                    [("gmail_message_id", ASCENDING)],
                    unique=True,
                    name="unique_gmail_message_id_raw_email"
                )
            logger.info("Index unique 'gmail_message_id_raw_email' créé pour filtered_emails")
            
            #================task 
            self.db.task.create_index(
                    [("task_id", ASCENDING)],
                    unique=True,
                    name="unique_task_id"
                )
            logger.info("Index unique 'task_id' créé pour filtered_emails")
            
        except OperationFailure as e:
            logger.error(f"Erreur lors de l'initialisation des indexes MongoDB : {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'init indexes MongoDB : {e}")
    #  mila REPLICA IZANY 
    
    # def add_config(self, data):
    #     """Met à jour la configuration et reconnecte automatiquement."""
    #     with self.config_client.start_session() as session:
    #         with session.start_transaction():
    #             self.stop_prev_config(session)
    #             result= self.config_collection.insert_one(data, session = session)
    #             # Recharge la config et reconnecte la base réelle
    #             self.config = self.config_collection.find_one({"is_active": True},session=session)
    #             self._connect_real_db()
#                  return result
    # def stop_prev_config(self, session):
    #     """Désactive toute configuration active."""
    #     self.config_collection.update_many(
    #         {"is_active": True},
    #         {"$set": {"is_active": False}},
    #         session=session
    #     )
    #     return True
    
    
    # # 
    def add_config(self, data):
        """Met à jour la configuration et reconnecte automatiquement."""
        self.stop_prev_config()
        result = self.config_collection.insert_one(data)
        # Recharge la config et reconnecte la base réelle
        self.config = self.config_collection.find_one({"is_active": True})
        self._connect_real_db()
        return result

    def stop_prev_config(self):
        """Désactive toute configuration active."""
        self.config_collection.update_many(
            {"is_active": True},
            {"$set": {"is_active": False}}
        )
        return True
    
    def  test_new_input_config(self,config):
        """
            Tester la noouvelle configuration et Afficher erreur si cette configuration n existe meme pas
        """
        try:
            # set the URI connexion
            username = username = config.get("username")
            password = config.get("password")
            host = config.get("host")
            port = config.get("port")
            db_name = config.get("db_name")
            # Si un nom d'utilisateur et un mot de passe sont fournis
            if not host or not db_name:
                raise ValueError("La configuration doit contenir au moins 'host' et 'db_name'.")
            if username and password:
                uri = f"mongodb://{username}:{password}@{host}:{port}/{db_name}"
            else:
                uri = f"mongodb://{host}:{port}/{db_name}"
              # Établir la connexion
            client = MongoClient(uri, serverSelectionTimeoutMS=5000)  # Timeout de 5 secondes
            client.server_info()  # Lève une exception si la connexion échoue
            # Lister les bases de données existantes
            database_names = client.list_database_names()
            if db_name not in database_names:
                raise ValueError("le nom de la base de donnée et introuvable")
             # Fermer la connexion
            client.close()
            logger.info("Connexion à MongoDB réussie !")
            return True
        except ConnectionFailure as e:
            logger.error(f"Échec de la connexion à MongoDB : {e}")
            raise ValueError(f"Échec de la connexion à MongoDB : {e}")
        except OperationFailure as e:
            logger.error(f"Échec de l'opération sur MongoDB : {e}")
            raise ValueError(f"Échec de l'opération sur MongoDB : {e}")
        except ConfigurationError as e:
           logger.error(f"Configuration MongoDB invalide : {e}")
           raise ValueError(f"Configuration MongoDB invalide : {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue : {e}")
            raise ValueError(f"Erreur inattendue : {e}")
# genelral
mongo_service = MongoDBService()
