from django.urls import path
from .views import trigger_notification

urlpatterns = [
    path('test', trigger_notification, name='trigger-notification'),
]