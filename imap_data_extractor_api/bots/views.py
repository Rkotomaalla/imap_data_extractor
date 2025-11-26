from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializer import BotSerializer
import logging
from django.db import transaction

logger = logging.getLogger(__name__)
# Create your views here.
class BotsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response({'success': True, 'message': 'Tongasoa ee'}, status=201)
    def post(self,request):
        """Creer un nouvel Bot"""
        data = request.data.copy()  # copier les données reçues
        data['assigned_user'] = request.user.username
        data['assigned_user_id'] = request.user.id 
        print(f"\n================================================={data}\n")
        serializer = BotSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()  # crée Bot + BotFilter + BotRules en une seule fois
        return Response({'success': True, 'message': 'Bot créé avec succès'}, status=201)
    