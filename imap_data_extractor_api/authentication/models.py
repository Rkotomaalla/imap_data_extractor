from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser


class LDAPUser(AbstractUser):
    """
    Modèle utilisateur synchronisé avec LDAP.
    Stocke les informations en cache de la session LDAP.
    """
    ldap_cn=models.CharField(        
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name="Distinguished Name LDAP"
    )
    
    ldap_roles = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Rôles LDAP"
    )
    
    last_ldap_sync = models.DateTimeField(
        auto_now=True,
        verbose_name="Dernière synchronisation LDAP"
    )
    
    class Meta:
        verbose_name = "Utilisateur LDAP"
        verbose_name_plural = "Utilisateurs LDAP"
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def has_ldap_role(self, role_name):
        """Vérifie si l'utilisateur a un rôle spécifique"""
        return any(role.get('name') == role_name for role in self.ldap_roles)