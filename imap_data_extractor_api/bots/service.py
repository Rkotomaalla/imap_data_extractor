from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta
from configurations.services import mongo_service
from imap_data_extractor_api.services import imap_data_extractor_api_services
from pymongo.errors import PyMongoError
from task.services import task_service
from datetime import datetime
from .serializer import BotSerializer , BotArchiveSerializer
from imap_data_extractor_api.utils import get_next_sequence_value
from outlook_integration.utils import outlook_utils
class BotService:   
    def __init__(self):
       self.collection =  mongo_service.get_collection('bot') 
       self.archive_collection = mongo_service.get_collection('bot_archive')
       self.STATUS_LABELS = {
            0: "Pause",
            1: "Marche",
            2: "Arrêté",
            3: "Supprimé"
        }
    def get_by_id(self, bot_id):
        try:
            bot_result = self.collection.find_one({"bot_id": bot_id})
            return bot_result
        except Exception as e:
            raise Exception(f"Une erreur s'est produite lors de la récupération du bot par son id : {str(e)}")
        
    def generate_bot_token(self,bot_id, assigned_user_id):
        """
        Génère un token JWT spécial pour un bot
        """
        token = AccessToken()
        token.set_exp(lifetime=timedelta(days=30))  # token valide 30 jours
        
        # Claims personnalisés pour identifier le bot
        token["is_bot"] = True
        token["bot_id"] = str(bot_id)
        token["assigned_user_id"] = str(assigned_user_id)
        token["type"] = "bot_access"
        
        # ⚠️ NE PAS ajouter user_id pour les bots
        # L'authentification personnalisée gère ce cas
        
        return str(token)   
    
    def is_bot_owner(self, id_bot, id_user,user_role):
        try:
            id_bot = int(id_bot)
            id_user = int(id_user)
        except ValueError:
            raise ValueError("IDs and id_user must be integers")
        try:
            if user_role == "admin":
                return True
            bot = self.collection.find_one(
                {
                    'bot_id':id_bot,
                    'assigned_user_id': id_user
                }   
            )
            return bot is not None
                
        except Exception as e:
            raise Exception(f"Erreur lors de la vérification de la propriété du bot: {str(e)}")            


    def update_status_bot(self, bot_id, int_value):
        try:
            bot_id = int(bot_id)
            status_value = int(int_value)

            result = self.collection.update_one(
                {"bot_id": bot_id},
                {"$set": {"status": status_value}}
            )

            if result.matched_count == 0:
                raise Exception("Bot introuvable")

            return {
                "matched": result.matched_count,
                "modified": result.modified_count
            }

        except ValueError:
            raise Exception("bot_id et status doivent être des entiers")

        except PyMongoError as e:
            raise Exception(
                f"Erreur MongoDB lors de la mise à jour du status du bot : {str(e)}"
            )
            
            
    def activate_bot(self,bot_id):
        """Activation du bot"""
        try:
            bot = self.get_by_id (bot_id)
            
            if not bot : 
                raise ValueError("bot non existant")
            
            user_id = bot["assigned_user_id"]
            outlook_collection  =  mongo_service.get_collection("outlook_token")
            
            # Récupérer le document Outlook de l'utilisateur
            token_doc = outlook_collection.find_one({"user_id" : user_id})
            if not token_doc or not token_doc.get("refresh_token"):
                raise Exception("Compte Outlook non connecté")            
            # count = collection.count_documents({"value": })
            if not token_doc.get("subscription_id"):
                subscription_id = outlook_utils.create_graph_subscription(user_id)
                if subscription_id:
                    outlook_collection.update_one(
                        {"user_id": user_id},
                        {"$set": {
                            "subscription_id": subscription_id,
                            "subscription_expires_at": datetime.utcnow() + timedelta(days=2, hours=23),  # max ~3 jours
                            "updated_at": datetime.utcnow()
                        }}
                    )     

            # if result.get('success'):
            self.update_status_bot(bot_id,1)
            created_task=task_service.create_task(bot_id,user_id)
            return created_task
        except Exception as e:
            raise Exception (f"Une erreur est survenue lors de l activation du bot acitvate_bot => {str(e)}")

    def delete_bot(self ,bot_id,user_id):
        """
            set_bot_status to 2 and set_date_deleted to now 
        """
        try:
            now = datetime.now()
            self.update_status_bot(bot_id, 3)
            updated_bot = self.collection.update_one(
                {
                    'bot_id' : bot_id
                },
                {'$set' : {
                    'killed_date' : now
                }})
            if updated_bot.matched_count == 0:
                # Aucun bot trouvé avec cet id
                raise Exception(f"Aucun bot trouvé avec l'id {bot_id}")
            if updated_bot.modified_count == 0:
                # Le document existait, mais aucune modification effectuée
                print("Le bot existait déjà avec ce killed_date ou aucune mise à jour nécessaire")
            bot_doc = self.get_by_id(bot_id)
            updated_bot_serializer = BotSerializer(bot_doc)
            archive_data={
                "bot_id" : bot_id,
                "bot" : updated_bot_serializer.data
            }
            
            serializer =  BotArchiveSerializer(data=archive_data)
            if serializer.is_valid(raise_exception=True):
                archive_data_to_insert = serializer.validated_data
                archive_data_to_insert["bot_archive_id"] = get_next_sequence_value ("bot_archive_id")
                archive_data_to_insert["deleted_at"] = now
                archive_data_to_insert["deleted_by"] = user_id
                print(f'\n=====================================================\n{archive_data_to_insert}\n=============================================================')

                result = self.archive_collection.insert_one(archive_data_to_insert)
                # if result.inserted_id:
                    # self.collection.delete_one({"bot_id" : bot_id})
        except Exception as e:
            raise Exception (f"Erreur est survenue lors de la suppression du bot service.delete_bot  {str(e)}")

    def stop_bot(self, bot_id):
        """
        Arrête le bot en mettant à jour son statut dans la base de données.
        """
        try:
            bot = self.get_by_id (bot_id)
            
            if not bot : 
                raise ValueError("bot non existant")
            
            user_id = bot["assigned_user_id"]
            outlook_collection  =  mongo_service.get_collection("outlook_token")
            
            # Récupérer le document Outlook de l'utilisateur
            token_doc = outlook_collection.find_one({"user_id" : user_id})
            if not token_doc or not token_doc.get("refresh_token"):
                raise Exception("Compte Outlook non connecté")     
            
            if bot.get("status") in (0, 1):
                self.update_status_bot(bot_id, 2 )
                count = outlook_collection.count_documents({
                    "value": {"$in": [1, 0]}
                })
                if count == 0:
                    if token_doc.get("subscription_id"):
                        outlook_utils.delete_graph_subscription(token_doc["subscription_id"])
                    outlook_collection.update_one(
                        {"user_id": user_id},
                        {"$set": {
                            "subscription_id": None,
                            "subscription_expires_at": None,
                            "updated_at": datetime.utcnow()
                        }}
                    )
                task_service.stop_task(bot_id)            
            else:
                raise Exception("Le bot est déjà arrêté")
        except Exception as e:
            raise Exception(f"Erreur lors de l'arrêt du bot: {str(e)}")

    def get_count_by_status(self, status):
        try:
            return self.collection.count_documents({"status": int(status)})
        except Exception as e:
            raise Exception(
                f"Erreur lors du count pour le status {status} : {str(e)}"
            )
            
    def get_count(self):
        try:
            count_bots= []
            for status, libelle in self.STATUS_LABELS.items():
                item = {
                    "total" :  self.get_count_by_status(status),
                    "libelle" : libelle
                }
                count_bots.append(item)
            return count_bots
        except Exception as e:
            raise Exception (f'Une erreur est survenue lors du traitement de la  fonction getCount : {str(e)}')

bot_service = BotService()