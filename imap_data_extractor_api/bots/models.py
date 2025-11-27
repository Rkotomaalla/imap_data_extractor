import uuid
from django.db import models
from django.utils.timezone import now

# class Status(models.IntegerChoices):
#     PAUSE  = 0
#     RUN = 1
#     KILLED = 2
    
# class Bots(models.Model):
#     id_bot = models.AutoField(primary_key=True)
#     name = models.CharField(max_length=255)
#     status = models.IntegerField(blank=False,null=False,choices=Status.choices)
#     descritpion = models.TextField()
#     assigned_user = models.CharField(max_length=255,blank=False, null=False)
#     assigned_user_id = models.IntegerField(blank=False, null=False)
#     created_at = models.DateTimeField(auto_now_add=True)
#     killed_at = models.DateTimeField(blank=True, null=True)