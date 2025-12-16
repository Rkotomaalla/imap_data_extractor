from django.conf import settings
from rest_framework.exceptions import ValidationError
from bson import ObjectId
from bson.errors import InvalidId
from configurations.services import mongo_service
from pymongo import ReturnDocument
class PyObjectId(ObjectId):
    """Custom ObjectId pour la validation DRF"""
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValidationError('Invalide ObjectId')
        return ObjectId(v)
    
def serialize_mongo_doc(doc):
    if doc and '_id' in doc:
        doc['id'] = str(doc['_id'])
        del doc['_id']
    return doc 

def parse_object_id(id_string):
    try:
        return ObjectId(id_string)
    except (InvalidId, TypeError):
        raise ValidationError({'id' : 'Invalide Object format'})
    

def get_next_sequence_value(sequence_name):
    """Génère un ID auto-increment pour MongoDB"""
    counters_collection = mongo_service.get_collection('counters')
    result = counters_collection.find_one_and_update(
        {'_id': sequence_name},
        {'$inc': {'sequence_value': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    if result is None:
        raise ValueError("Échec de la génération de l'ID auto-incrémenté.")
    return result['sequence_value']


def get_next_version_value(collection,config_label):
    """Génère un ID auto-increment pour MongoDB"""
    result = collection.find_one_and_update(
        {'_id': config_label},
        {'$inc': {'version_value': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    if result is None:
        raise ValueError("Échec de la génération de l'ID auto-incrémenté.")
    return result['version_value']