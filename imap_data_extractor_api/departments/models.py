from django.db import models

# Create your models here.
class Department(models.Model):
    name =  models.CharField(max_length=100, unique=True)
    
    class Meta:
        verbose_name = 'Department'
        verbose_name_plural = 'Departments'
        ordering = ['name']
        
    def __str__(self):
        return self.name   