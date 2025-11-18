from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from .services.ldap_service import LDAPService
from rest_framework.response import Response
from rest_framework import status
import logging
# Create your views here.
logger=logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_department(request):
    """
    Récupère tous les départements depuis la base LDAP.
    
    GET /api/departments/
    
    Response 200:
    [
        {
            "name": "Informatique"
        },
        {
            "name": "Ressources Humaines"
        }
    ]
    
    Response 500 - Erreur serveur:
    {
        "success": false,
        "message": "Erreur lors de la récupération des départements"
    }
    """
    try:
        ldap_service = LDAPService()
        departments = ldap_service.get_all()
        department_list = [{'name': dept} for dept in departments]
        return Response(department_list, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des départements: {e}")
        return Response(
            {
                "success": False,
                "message": "Erreur lors de la récupération des départements"
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )