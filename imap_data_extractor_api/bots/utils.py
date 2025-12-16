# from bson import ObjectId
# from django.conf import settings

# from bson.errors import InvalidId
# from rest_framework.exceptions import ValidationError


# class PyObjectId(ObjectId):
#     """Custom ObjectId pour la validation DRF"""
#     @classmethod
#     def validate(cls, v):
#         if not ObjectId.is_valid(v):
#             raise ValidationError('Invalide ObjectId')
#         return ObjectId(v)
    
# def serialize_mongo_doc(doc):
#     if doc and '_id' in doc:
#         doc['id'] = str(doc['_id'])
#         del doc['_id']
#     return doc 

# def parse_object_id(id_string):
#     try:
#         return ObjectId(id_string)
#     except (InvalidId, TypeError):
#         raise ValidationError({'id' : 'Invalide Object format'})
    
# def get_next_sequence_value(sequence_name):
#     """Génère un ID auto-increment pour MongoDB"""
#     counters_collection = settings.MiONGO_DB.get_collection('counters')
#     result = counters_collection.find_one_and_update(
#         {'_id': sequence_name},
#         {'$inc': {'sequence_value': 1}},
#         upsert=True,
#         return_document=True
#     )
#     return result['sequence_value']
