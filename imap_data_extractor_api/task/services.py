from configurations.services import mongo_service
from datetime import datetime
from .serializer import TaskSerializer
from imap_data_extractor_api.utils import get_next_sequence_value , serialize_mongo_doc
from datetime import datetime
class TaskService:
    def __init__(self):
        self.collection = mongo_service.get_collection('task')
    
    # def create_task(self, id_bot):
    #     pass

#CREATION  d une tache======================================================================================================
    def create_task(self,bot_id,user_id):
        try:
            task = {
                'bot_id' : bot_id, 
                'started_by' : user_id,
                'started_at' : datetime.now()
            } 
            serializer = TaskSerializer(data = task)
            if serializer.is_valid(raise_exception=True):
                task_to_insert = serializer.validated_data
                task_to_insert['task_id'] = get_next_sequence_value('task_id')
                result =  self.collection.insert_one(task_to_insert)
                data_inserted =  self.collection.find_one({'_id' : result.inserted_id})
                data_inserted =  serialize_mongo_doc(data_inserted)
                response_serializer =  TaskSerializer(data_inserted)
                return response_serializer.data
        except Exception as e:
            raise Exception(f"Une erreur est survenue lors de la creation de le tache {str(e)}")
#Arret d une tache======================================================================================================
    def stop_task(self, bot_id):
        try:
            task=self.collection.update_one({
                "bot_id" :  bot_id ,
                "date_ended" : None
            },
            {
                "$set" : {
                    "date_ended" : datetime.now()    
                }  
            }   
            )
            return task;
        except Exception as e:
            raise Exception(f"Une Erreur inatendue est survenue dans task.TaskService {str(e)}")
       
task_service = TaskService()