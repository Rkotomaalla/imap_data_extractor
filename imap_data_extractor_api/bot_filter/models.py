from django.db import models
import uuid
# from bots.models import Bots


    
# class Action(models.IntegerChoices):
#     DELETE = 0
#     SAVE = 1
    
# class Field(models.Model):
#     id_field=models.AutoField(primary_key=True)
#     name=models.CharField(max_length=255)
    
# class Operator(models.Model):
#     id_operator=models.AutoField(primary_key=True)  
#     name=models.CharField(max_length=255)
#     field=models.ForeignKey(Field,on_delete=models.CASCADE,related_name='operators')
    
# class BotFilter(models.Model):
#     id_filter=models.AutoField(primary_key=True)
#     name=models.CharField(max_length=255)
#     required_all=models.BooleanField(blank=False,null=False)
#     bot=models.OneToOneField(Bots,on_delete=models.CASCADE, related_name='filter')
#     action=models.IntegerField(choices=Action.choices,blank=False,null=False)

# class BotRule(models.Model):
#     id_rule=models.AutoField(primary_key=True)
#     bot_filter=models.ForeignKey(BotFilter,on_delete=models.CASCADE,related_name='rules')
#     field=models.ForeignKey(Field,on_delete=models.CASCADE,related_name='field_rules')
#     operator=models.ForeignKey(Operator,on_delete=models.CASCADE,related_name='operator_rules')
#     value=models.TextField()
    
