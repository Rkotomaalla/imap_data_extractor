from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .services import send_hello_world_notification

@api_view(['POST'])
def trigger_notification(request):
    # Logique métier...
    send_hello_world_notification()
    return Response({'status': 'Notification sent'})