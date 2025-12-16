# from django.conf import settings

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

# def serialize_mongo_doc(doc):
#     if doc and '_id' in doc:
#         doc['id'] = str(doc['_id'])
#         del doc['_id']
#     return doc 